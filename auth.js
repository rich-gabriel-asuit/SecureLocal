const express = require('express');
const bcrypt = require('bcrypt');
const { rateLimit } = require('express-rate-limit');
const db = require('../../db/database');
const { audit } = require('../security');
const router = express.Router();
const MAX_FAILED = 5;
const LOCK_MINUTES = 15;
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
router.use(limiter);
const commonPasswords = new Set(['password1234','123456789012','qwerty123456','admin123456','iloveyou1234','passwordpassword','securelocal123']);
const wantsHtml = (req) => req.accepts('html') && !req.is('application/json');
function renderRegister(req, res, status, error, username = '', email = '') { return res.status(status).render('register', { error, username, email }); }
function renderLogin(req, res, status, error, username = '') { return res.status(status).render('login', { error, username, registered: false }); }
function passwordError(password, username) {
  if (password.length < 12) return 'Password must contain at least 12 characters.';
  if (Buffer.byteLength(password, 'utf8') > 72) return 'Password must be no more than 72 UTF-8 bytes.';
  if (password.toLowerCase().includes(username.toLowerCase())) return 'Password must not contain your username.';
  if (commonPasswords.has(password.toLowerCase())) return 'Choose a less common password.';
  return null;
}
router.post('/register', async (req, res) => {
  const { username, email, password, consent } = req.body || {};
  if (![username,email,password].every((v) => typeof v === 'string')) return renderRegister(req,res,400,'Please complete all fields.');
  const name = username.trim(); const mail = email.trim().toLowerCase();
  if (!/^[A-Za-z0-9_]{3,30}$/.test(name)) return renderRegister(req,res,400,'Username must be 3–30 letters, numbers or underscores.',name,mail);
  if (mail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return renderRegister(req,res,400,'Enter a valid email address.',name,mail);
  if (consent !== 'yes') return renderRegister(req,res,400,'Please read and accept the privacy notice to continue.',name,mail);
  const pError = passwordError(password,name); if (pError) return renderRegister(req,res,400,pError,name,mail);
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (username,email,password_hash,role,consent_accepted_at) VALUES (?,?,?,\'Customer\',?)').run(name,mail,hash,new Date().toISOString());
    audit(result.lastInsertRowid,'USER_REGISTERED','Customer account registered with privacy consent.',req);
    return res.redirect('/login?registered=1');
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return renderRegister(req,res,409,'Username or email is already registered.',name,mail);
    console.error('Registration error:',e); return renderRegister(req,res,500,'Registration failed. Please try again.',name,mail);
  }
});
router.post('/login', async (req,res) => {
  const { username,password } = req.body || {};
  const name = typeof username === 'string' ? username.trim() : '';
  if (!name || typeof password !== 'string' || !password) return renderLogin(req,res,400,'Invalid username or password.',name);
  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(name);
    if (!user) { audit(null,'LOGIN_FAILED','Login attempted for unknown username.',req); return renderLogin(req,res,401,'Invalid username or password.',name); }
    if (user.locked_until && Date.parse(user.locked_until) > Date.now()) { audit(user.id,'LOGIN_BLOCKED','Login blocked while account lockout is active.',req); return renderLogin(req,res,423,'Account temporarily locked. Try again after 15 minutes.',name); }
    if (user.locked_until) db.prepare('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?').run(user.id);
    const valid = await bcrypt.compare(password,user.password_hash);
    if (!valid) {
      const attempts = (user.failed_attempts || 0) + 1;
      if (attempts >= MAX_FAILED) {
        const until = new Date(Date.now()+LOCK_MINUTES*60000).toISOString();
        db.prepare('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?').run(attempts,until,user.id);
        audit(user.id,'ACCOUNT_LOCKED','Account locked after five failed login attempts.',req);
        return renderLogin(req,res,423,'Account temporarily locked after repeated failed attempts.',name);
      }
      db.prepare('UPDATE users SET failed_attempts=? WHERE id=?').run(attempts,user.id);
      audit(user.id,'LOGIN_FAILED',`Incorrect password; failed attempt ${attempts}.`,req);
      return renderLogin(req,res,401,'Invalid username or password.',name);
    }
    db.prepare('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?').run(user.id);
    req.session.regenerate((err) => {
      if (err) return renderLogin(req,res,500,'Unable to start a secure session.');
      if (user.mfa_enabled) {
        req.session.pendingMfaUserId = user.id;
        return req.session.save(() => res.redirect('/mfa/verify'));
      }
      req.session.user = { id:user.id, username:user.username, role:user.role };
      req.session.mfaVerifiedAt = null;
      req.session.save((saveErr) => {
        if (saveErr) return renderLogin(req,res,500,'Unable to start a secure session.');
        audit(user.id,'LOGIN_SUCCESS','User logged in without MFA.',req);
        if (user.role === 'Admin') audit(user.id,'ADMIN_LOGIN_MFA_REQUIRED','Admin signed in; MFA setup is required before admin access.',req);
        res.redirect('/dashboard');
      });
    });
  } catch(e) { console.error('Login error:',e); return renderLogin(req,res,500,'Login failed. Please try again.',name); }
});
router.post('/logout',(req,res) => {
  if (req.session?.user) audit(req.session.user.id,'LOGOUT','User logged out.',req);
  req.session.destroy((err) => {
    if (err) return res.status(500).send('Logout failed.');
    res.clearCookie('securelocal.sid',{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production'});
    res.redirect('/');
  });
});
module.exports = router;
