import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import QRCode from 'qrcode'
import http from 'http'
import { Server as SocketIOServer } from 'socket.io'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { initDb, createSession as dbCreateSession, saveToken as dbSaveToken, saveShortCode as dbSaveShortCode, deactivateToken as dbDeactivateToken, deleteShortCode as dbDeleteShortCode, markPresent as dbMarkPresent, enrollStudent as dbEnrollStudent, unenrollStudent as dbUnenrollStudent, getEnrollments as dbGetEnrollments, isEnrolled as dbIsEnrolled, getEnrollmentRecords as dbGetEnrollmentRecords, createStudent as dbCreateStudent, getStudentByRegNo as dbGetStudentByRegNo } from './db.js'

const app = express()
initDb()
const server = http.createServer(app)
const allowedOrigins = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map(s => s.trim())
const io = new SocketIOServer(server, { cors: { origin: allowedOrigins, methods: ['GET','POST'] } })

app.use(cors({ origin: allowedOrigins }))
app.use(express.json())

// One-time seed for requested data
;(async function seedOnce(){
  try {
    const courseId = '21CS701'
    const students = [
      'ES22CJ27','ES22CJ56','ES22CJ07','ES22CJ41','ES22CJ35','ES22CJ57','ES22CJ08','ES22CJ12','ES22CJ61','ES22CJ59','ES22CJ52','ES22CJ49','ES22CJ58','ES22CJ36','ES22CJ26','ES22CJ21','ES22CJ24','ES22CJ60','ES22CJ30','ES22CJ31','ES22CJ17','ES22CJ63','ES22CJ47','ES22CJ06','ES22CJ23','ES22CJ11','ES22CJ42','ES22CJ01','ES22CJ28','ES22CJ18','ES22CJ40','ES22CJ48','ES22CJ55'
    ]
    const existing = await dbGetEnrollments(courseId)
    if (!existing || existing.length === 0) {
      for (const sid of students) { await dbEnrollStudent(courseId, sid) }
      console.log(`[seed] Enrolled ${students.length} students to ${courseId}`)
    }
    const staffEmail = 'kiruthika@demo.com'
    const { getStaffByEmail, createStaff } = await import('./db.js')
    const found = await getStaffByEmail(staffEmail)
    if (!found) {
      await createStaff({ id: staffEmail, name: 'Kiruthika', email: staffEmail, password: 'kiruthika123' })
      console.log('[seed] Created staff user kiruthika@demo.com')
    }
  } catch (e) {
    console.warn('[seed] skipped or failed:', e?.message)
  }
})()

// Allow clients to call API under '/api' as well as root paths
// This rewrites '/api/qr/generate' -> '/qr/generate', etc.
app.use((req, _res, next) => {
  if (req.url.startsWith('/api/')) {
    req.url = req.url.slice(4)
  } else if (req.url === '/api') {
    req.url = '/'
  }
  next()
})

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'

// In-memory stores for demo
const sessions = new Map() // sessionId -> { courseId, startTime, endTime, status, windowSeconds, present:Set<string>, enrolled:Set<string>, currentTokenJti, tokenExpiresAt }
const tokens = new Map() // jti -> { sessionId, expiresAt, active, code? }
const shortCodes = new Map() // code -> jti

// Enrollments backed by DB (see db.js)

function generateToken(sessionId) {
  const jti = `${sessionId}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
  const iat = Math.floor(Date.now() / 1000)
  const exp = iat + 30
  const token = jwt.sign({ jti, sid: sessionId, iat, exp, ver: 1 }, JWT_SECRET, { algorithm: 'HS256' })
  // create 6-char short code [A-Z0-9]
  let code
  do {
    code = Math.random().toString(36).slice(2, 8).toUpperCase()
  } while (shortCodes.has(code))
  tokens.set(jti, { sessionId, expiresAt: exp * 1000, active: true, code })
  shortCodes.set(code, jti)
  // persist
  try { dbSaveToken({ jti, sessionId, expiresAt: exp * 1000, active: 1, code }); dbSaveShortCode(code, jti) } catch {}
  return { token, jti, exp }
}

function scheduleExpiry(jti) {
  const t = tokens.get(jti)
  if (!t) return
  const delay = Math.max(0, t.expiresAt - Date.now())
  setTimeout(() => {
    const tok = tokens.get(jti)
    if (tok) tok.active = false
    if (tok?.code) shortCodes.delete(tok.code)
    try { if (tok) dbDeactivateToken(jti); if (tok?.code) dbDeleteShortCode(tok.code) } catch {}
    const sess = sessions.get(t.sessionId)
    if (sess && sess.currentTokenJti === jti) {
      // window expired; keep session active to allow new generations
      io.to(`session:${t.sessionId}`).emit('session_closed', {
        sessionId: t.sessionId,
        summary: {
          present: sess.present.size,
          total: sess.enrolled.size,
          absent: Math.max(0, sess.enrolled.size - sess.present.size)
        }
      })
      // clear the current QR marker so clients know it's gone
      sess.currentTokenJti = null
      sess.tokenExpiresAt = null
    }
  }, delay)
}

// Socket.IO
io.on('connection', (socket) => {
  socket.on('subscribe', ({ sessionId }) => {
    socket.join(`session:${sessionId}`)
    const sess = sessions.get(sessionId)
    if (sess && sess.currentTokenJti) {
      const expMs = sess.tokenExpiresAt
      const secondsRemaining = Math.max(0, Math.ceil((expMs - Date.now()) / 1000))
      socket.emit('countdown', { secondsRemaining })
    }
  })
  socket.on('unsubscribe', ({ sessionId }) => {
    socket.leave(`session:${sessionId}`)
  })
})

// Routes

// Create session (teacher/admin)
app.post('/sessions', async (req, res) => {
  const { courseId, windowSeconds = 30 } = req.body || {}
  if (!courseId) return res.status(400).json({ error: 'courseId_required' })
  const sessionId = `S_${Date.now()}`
  const enrolledList = await dbGetEnrollments(courseId)
  const enrolled = new Set(enrolledList)
  const session = {
    courseId,
    startTime: Date.now(),
    endTime: null,
    status: 'active',
    windowSeconds,
    present: new Set(),
    enrolled: new Set(enrolled),
    currentTokenJti: null,
    tokenExpiresAt: null
  }
  sessions.set(sessionId, session)
  try { dbCreateSession({ id: sessionId, courseId, startTime: session.startTime, endTime: null, status: 'active', windowSeconds, currentTokenJti: null, tokenExpiresAt: null }) } catch {}

  const { token, jti, exp } = generateToken(sessionId)
  session.currentTokenJti = jti
  session.tokenExpiresAt = exp * 1000
  scheduleExpiry(jti)

  QRCode.toDataURL(token).then((imageDataUrl) => {
    const code = tokens.get(jti)?.code
    io.to(`session:${sessionId}`).emit('qr_updated', { imageDataUrl, token, code, expiresAt: new Date(exp * 1000).toISOString(), jti })
  }).catch(() => {})

  return res.json({ sessionId, status: session.status, startTime: session.startTime, windowSeconds })
})

// Current QR fetch (optional)
app.get('/sessions/:sessionId/qr', (req, res) => {
  const { sessionId } = req.params
  const sess = sessions.get(sessionId)
  if (!sess) return res.status(404).json({ error: 'not_found' })
  const jti = sess.currentTokenJti
  if (!jti) return res.status(404).json({ error: 'no_token' })
  const exp = Math.floor(sess.tokenExpiresAt / 1000)
  const token = jwt.sign({ jti, sid: sessionId, iat: Math.floor(Date.now()/1000), exp, ver: 1 }, JWT_SECRET)
  const code = tokens.get(jti)?.code
  QRCode.toDataURL(token).then((imageDataUrl) => {
    res.json({ imageDataUrl, token, code, expiresAt: new Date(exp * 1000).toISOString(), jti })
  }).catch(() => res.status(500).json({ error: 'qr_error' }))
})

// Student scan
app.post('/attendance/scan', async (req, res) => {
  const { token, studentId = 'student1' } = req.body || {}
  if (!token) return res.status(400).json({ error: 'token_required' })
  try {
    const cleaned = String(token).trim().toUpperCase()
    let jti
    let sessionId
    if (cleaned.includes('.')) {
      const payload = jwt.verify(cleaned, JWT_SECRET)
      jti = payload.jti
      sessionId = payload.sid
    } else {
      const mapped = shortCodes.get(cleaned)
      if (!mapped) return res.status(400).json({ error: 'invalid_code' })
      jti = mapped
      const tokRec = tokens.get(jti)
      sessionId = tokRec?.sessionId
    }
    const tok = tokens.get(jti)
    if (!tok || tok.sessionId !== sessionId) return res.status(400).json({ error: 'invalid_code' })
    if (!tok.active) return res.status(409).json({ error: 'already_used' })
    const sess = sessions.get(sessionId)
    if (!sess) return res.status(410).json({ error: 'session_closed' })
    if (Date.now() >= tok.expiresAt) return res.status(410).json({ error: 'expired_code' })
    const enrolled = await dbIsEnrolled(sess.courseId, studentId)
    if (!enrolled) return res.status(403).json({ error: 'not_enrolled' })

    sess.present.add(studentId)
    tok.active = false
    if (tok.code) shortCodes.delete(tok.code)
    try { dbMarkPresent(sessionId, studentId); dbDeactivateToken(jti); if (tok.code) dbDeleteShortCode(tok.code) } catch {}

    io.to(`session:${sessionId}`).emit('scan_confirmed', {
      sessionId,
      countPresent: sess.present.size,
      countRemaining: Math.max(0, sess.enrolled.size - sess.present.size)
    })

    return res.json({ status: 'present', sessionId, markedAt: new Date().toISOString() })
  } catch (e) {
    console.error('Scan validate error:', e)
    if (e.name === 'TokenExpiredError') return res.status(410).json({ error: 'expired_code' })
    return res.status(400).json({ error: 'invalid_code', message: e?.message })
  }
})

// Generate QR on-demand (new token per click). If sessionId missing or invalid, start new session
app.post('/qr/generate', async (req, res) => {
  try {
    const { sessionId: providedSessionId, courseId = 'COURSE1' } = req.body || {}
    if (!courseId) return res.status(400).json({ error: 'course_required', message: 'courseId is required' })
    let sessionId = providedSessionId
    let sess = sessionId && sessions.get(sessionId)
    if (!sess) {
      // create new session
      sessionId = `S_${Date.now()}`
      const enrolledList = await dbGetEnrollments(courseId)
      const enrolled = new Set(enrolledList)
      sess = {
        courseId,
        startTime: Date.now(),
        endTime: null,
        status: 'active',
        windowSeconds: 30,
        present: new Set(),
        enrolled: new Set(enrolled),
        currentTokenJti: null,
        tokenExpiresAt: null
      }
      sessions.set(sessionId, sess)
    }

    // Deactivate any previously active token for this session
    if (sess.currentTokenJti && tokens.has(sess.currentTokenJti)) {
      const prev = tokens.get(sess.currentTokenJti)
      prev.active = false
      if (prev.code) shortCodes.delete(prev.code)
    }
    const { token, jti, exp } = generateToken(sessionId)
    sess.currentTokenJti = jti
    sess.tokenExpiresAt = exp * 1000
    scheduleExpiry(jti)

    try {
      const imageDataUrl = await QRCode.toDataURL(token)
      const code = tokens.get(jti)?.code
      io.to(`session:${sessionId}`).emit('qr_updated', { imageDataUrl, token, code, expiresAt: new Date(exp * 1000).toISOString(), jti })
      io.to(`session:${sessionId}`).emit('countdown', { secondsRemaining: 30 })
      return res.json({ sessionId, imageDataUrl, token, code, expiresAt: new Date(exp * 1000).toISOString(), jti })
    } catch (imgErr) {
      console.error('QR image generation failed, falling back to token-only:', imgErr)
      // Emit token so clients can render QR locally
      const code = tokens.get(jti)?.code
      io.to(`session:${sessionId}`).emit('qr_updated', { imageDataUrl: null, token, code, expiresAt: new Date(exp * 1000).toISOString(), jti })
      io.to(`session:${sessionId}`).emit('countdown', { secondsRemaining: 30 })
      return res.json({ sessionId, imageDataUrl: null, token, code, expiresAt: new Date(exp * 1000).toISOString(), jti, clientRender: true })
    }
  } catch (e) {
    console.error('QR generate error:', e)
    return res.status(500).json({ error: 'qr_error', message: e?.message || 'QR generation failed' })
  }
})

// Close session explicitly (teacher/admin)
app.post('/sessions/:sessionId/close', (req, res) => {
  const { sessionId } = req.params
  const sess = sessions.get(sessionId)
  if (!sess) return res.status(404).json({ error: 'not_found' })
  if (sess.status === 'closed' || sess.status === 'expired') {
    return res.json({ sessionId, status: sess.status, endTime: sess.endTime })
  }
  sess.status = 'closed'
  sess.endTime = Date.now()
  // deactivate current token
  if (sess.currentTokenJti && tokens.has(sess.currentTokenJti)) {
    tokens.get(sess.currentTokenJti).active = false
  }
  io.to(`session:${sessionId}`).emit('session_closed', {
    sessionId,
    summary: {
      present: sess.present.size,
      total: sess.enrolled.size,
      absent: Math.max(0, sess.enrolled.size - sess.present.size)
    }
  })
  return res.json({ sessionId, status: sess.status, endTime: sess.endTime })
})

// Staff auth
app.post('/auth/staff/login', async (req, res) => {
  const { email, password } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' })
  // normalize email to allow users who cannot type '@' (e.g., 'name[domain.com]')
  let normalized = String(email).trim().toLowerCase()
  if (!normalized.includes('@')) {
    // common variants: name[domain.com], name(domain.com), name at domain.com
    normalized = normalized
      .replace(/\s+at\s+/g, '@')
      .replace(/[\[\(]/, '@')
      .replace(/[\]\)]/, '')
  }
  const staff = await (await import('./db.js')).getStaffByEmail(normalized)
  if (!staff || staff.password !== password) return res.status(401).json({ error: 'invalid_credentials' })
  return res.json({ id: staff.id, name: staff.name, email: staff.email, role: 'staff' })
})

// Student auth (regNo as username)
app.post('/auth/student/login', async (req, res) => {
  const { regNo, password } = req.body || {}
  if (!regNo || !password) return res.status(400).json({ error: 'regno_password_required' })
  const normalized = String(regNo).replace(/\s+/g, '').trim()
  const student = await dbGetStudentByRegNo(normalized)
  if (!student || student.password !== password) return res.status(401).json({ error: 'invalid_credentials' })
  return res.json({ role: 'student', regNo: student.regNo, studentId: student.studentId, name: student.name })
})

// Seed student accounts from enrollments for a course (regNo as username, default password)
app.post('/courses/:courseId/students/seed', async (req, res) => {
  const { courseId } = req.params
  const { password = 'student123' } = req.body || {}
  const records = await dbGetEnrollmentRecords(courseId)
  let created = 0
  for (const r of records) {
    if (!r?.regNo) continue
    const exists = await dbGetStudentByRegNo(r.regNo)
    if (!exists) {
      await dbCreateStudent({ regNo: r.regNo, studentId: r.studentId, name: r.name, password })
      created++
    }
  }
  return res.json({ courseId, created })
})

// GET convenience: seed with default password
app.get('/courses/:courseId/students/seed', async (req, res) => {
  const { courseId } = req.params
  const password = 'student123'
  const records = await dbGetEnrollmentRecords(courseId)
  let created = 0
  for (const r of records) {
    if (!r?.regNo) continue
    const exists = await dbGetStudentByRegNo(r.regNo)
    if (!exists) {
      await dbCreateStudent({ regNo: r.regNo, studentId: r.studentId, name: r.name, password })
      created++
    }
  }
  return res.json({ courseId, created, password })
})

// Staff CRUD
app.get('/staff', async (_req, res) => {
  const list = await (await import('./db.js')).listStaff()
  res.json(list)
})

app.post('/staff', async (req, res) => {
  let { id, name, email, password } = req.body || {}
  if (!email || !password || !name) return res.status(400).json({ error: 'name_email_password_required' })
  if (!id) id = String(email).toLowerCase()
  const doc = await (await import('./db.js')).createStaff({ id, name, email, password })
  res.status(201).json(doc)
})

// Bulk enroll students to a course
app.post('/courses/:courseId/enroll/bulk', async (req, res) => {
  const { courseId } = req.params
  const { students } = req.body || {}
  if (!Array.isArray(students) || students.length === 0) return res.status(400).json({ error: 'students_array_required' })
  for (const entry of students) {
    if (!entry) continue
    if (typeof entry === 'string') {
      await dbEnrollStudent(courseId, String(entry))
    } else if (typeof entry === 'object' && entry.studentId) {
      await dbEnrollStudent(courseId, String(entry.studentId), entry.name, entry.regNo)
    }
  }
  // Update active session caches
  for (const [sid, sess] of sessions.entries()) {
    if (sess.courseId === courseId) {
      for (const s of students) {
        const id = typeof s === 'string' ? s : s.studentId
        if (id) sess.enrolled.add(String(id))
      }
    }
  }
  const list = await (await import('./db.js')).getEnrollmentRecords(courseId)
  res.json({ courseId, count: list.length, students: list })
})

// Bulk set or update names for existing enrollments
app.post('/courses/:courseId/enroll/names', async (req, res) => {
  const { courseId } = req.params
  const { items } = req.body || {}
  if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'items_array_required' })
  const { setEnrollmentName, getEnrollmentRecords } = await import('./db.js')
  for (const it of items) {
    if (it?.studentId && typeof it.name === 'string') {
      await setEnrollmentName(courseId, String(it.studentId), it.name)
    }
  }
  const list = await getEnrollmentRecords(courseId)
  res.json({ courseId, students: list })
})

// Simple form to paste names (one per line) mapped by current enrollment order
app.get('/courses/:courseId/enroll/names/form', async (req, res) => {
  const { courseId } = req.params
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>Upload Names</title></head><body style="font-family: sans-serif; padding:20px">
  <h2>Paste Names for ${courseId}</h2>
  <p>Paste one name per line, in the same order as the student IDs.</p>
  <form method="post" action="/courses/${courseId}/enroll/names/raw">
    <textarea name="names" style="width:600px;height:300px"></textarea><br/>
    <button type="submit">Apply</button>
  </form>
  </body></html>`)
})

// Accept raw names (text/plain or form field) and map by order to existing enrollments for the course
app.post('/courses/:courseId/enroll/names/raw', express.urlencoded({ extended: true }), async (req, res) => {
  const { courseId } = req.params
  let raw = req.body?.names
  if (!raw && req.is('text/*')) {
    raw = await new Promise(resolve => {
      let data = ''
      req.setEncoding('utf8')
      req.on('data', chunk => data += chunk)
      req.on('end', () => resolve(data))
    })
  }
  if (!raw || typeof raw !== 'string') return res.status(400).json({ error: 'names_required' })
  const names = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean)
  const { setEnrollmentName, getEnrollmentRecords } = await import('./db.js')
  // get current enrollments in insertion order
  const records = await getEnrollmentRecords(courseId)
  const count = Math.min(names.length, records.length)
  for (let i = 0; i < count; i++) {
    await setEnrollmentName(courseId, records[i].studentId, names[i])
  }
  const updated = await getEnrollmentRecords(courseId)
  res.json({ courseId, updated: count, total: updated.length, students: updated })
})

// Form to paste names that will be applied ONLY to records missing a name, in order
app.get('/courses/:courseId/enroll/names/missing/form', async (req, res) => {
  const { courseId } = req.params
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>Fill Missing Names</title></head><body style="font-family: sans-serif; padding:20px">
  <h2>Fill Missing Names for ${courseId}</h2>
  <p>Paste one name per line. They will be assigned to students who are currently missing a name, in order.</p>
  <form method="post" action="/courses/${courseId}/enroll/names/missing/raw">
    <textarea name="names" style="width:600px;height:300px"></textarea><br/>
    <button type="submit">Apply</button>
  </form>
  </body></html>`)
})

// Apply pasted names only to enrollments that currently lack a name (order-based)
app.post('/courses/:courseId/enroll/names/missing/raw', express.urlencoded({ extended: true }), async (req, res) => {
  const { courseId } = req.params
  let raw = req.body?.names
  if (!raw && req.is('text/*')) {
    raw = await new Promise(resolve => {
      let data = ''
      req.setEncoding('utf8')
      req.on('data', chunk => data += chunk)
      req.on('end', () => resolve(data))
    })
  }
  if (!raw || typeof raw !== 'string') return res.status(400).json({ error: 'names_required' })
  const names = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean)
  const { setEnrollmentName, getEnrollmentRecords } = await import('./db.js')
  const records = await getEnrollmentRecords(courseId)
  const missing = records.filter(r => !r.name)
  const count = Math.min(names.length, missing.length)
  for (let i = 0; i < count; i++) {
    await setEnrollmentName(courseId, missing[i].studentId, names[i])
  }
  const updated = await getEnrollmentRecords(courseId)
  res.json({ courseId, filled: count, totalMissingBefore: missing.length, students: updated })
})

// Quick helper: set a single student's name via query parameters (local convenience)
// GET /courses/:courseId/enroll/names/quick?sid=ES22CJ24&name=KOMALA
app.get('/courses/:courseId/enroll/names/quick', async (req, res) => {
  const { courseId } = req.params
  const sid = String(req.query.sid || '').trim()
  const name = String(req.query.name || '').trim()
  if (!sid || !name) return res.status(400).json({ error: 'sid_and_name_required' })
  const { setEnrollmentName, getEnrollmentRecords } = await import('./db.js')
  await setEnrollmentName(courseId, sid, name)
  const list = await getEnrollmentRecords(courseId)
  res.json({ courseId, updated: { studentId: sid, name }, students: list })
})

// Staff: manage course enrollments
app.get('/courses/:courseId/enrollments', async (req, res) => {
  const { courseId } = req.params
  const { getEnrollmentRecords } = await import('./db.js')
  const records = await getEnrollmentRecords(courseId)
  return res.json({ courseId, students: records })
})

app.post('/courses/:courseId/enroll', async (req, res) => {
  const { courseId } = req.params
  const { studentId, name } = req.body || {}
  if (!studentId) return res.status(400).json({ error: 'studentId_required' })
  await dbEnrollStudent(courseId, studentId, name)
  // Update any active session cache for this course
  for (const [sid, sess] of sessions.entries()) {
    if (sess.courseId === courseId) sess.enrolled.add(studentId)
  }
  return res.json({ courseId, studentId, name, status: 'enrolled' })
})

// Delete all enrollments for a course
app.delete('/courses/:courseId/enrollments', async (req, res) => {
  const { courseId } = req.params
  const { clearEnrollments, getEnrollmentRecords } = await import('./db.js')
  await clearEnrollments(courseId)
  // Also clear any cached in-memory sets for active sessions
  for (const [sid, sess] of sessions.entries()) {
    if (sess.courseId === courseId) sess.enrolled.clear()
  }
  const list = await getEnrollmentRecords(courseId)
  res.json({ courseId, deleted: true, students: list })
})

// Simple upload form for ID, RegNo, Name lines
app.get('/courses/:courseId/enroll/upload/form', async (req, res) => {
  const { courseId } = req.params
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>Upload Enrollments</title></head><body style="font-family: sans-serif; padding:20px">
  <h2>Upload Enrollments for ${courseId}</h2>
  <p>Paste rows as: ID, RegNo, Name (comma- or tab-separated). Optionally clear existing first.</p>
  <form method="post" action="/courses/${courseId}/enroll/upload/raw">
    <label><input type="checkbox" name="clearFirst" /> Clear existing enrollments</label><br/><br/>
    <textarea name="rows" style="width:700px;height:320px" placeholder="ES22CJ41,730422553,MAHESHWARAN\nES22CJ26,730422553,VENGADESHVARAN\n..."></textarea><br/>
    <button type="submit">Import</button>
  </form>
  </body></html>`)
})

// Handle raw pasted rows and import
app.post('/courses/:courseId/enroll/upload/raw', express.urlencoded({ extended: true }), async (req, res) => {
  const { courseId } = req.params
  const clearFirst = req.body?.clearFirst === 'on'
  let raw = req.body?.rows || ''
  if (clearFirst) {
    const { clearEnrollments } = await import('./db.js')
    await clearEnrollments(courseId)
  }
  const lines = String(raw).split(/\r?\n/).map(s => s.trim()).filter(Boolean)
  let imported = 0
  for (const line of lines) {
    const parts = line.split(/[\t,]+/).map(s => s.trim()).filter(Boolean)
    if (parts.length < 3) continue
    const studentId = parts[0]
    const regNo = (parts[1] || '').replace(/[^0-9]/g, '')
    const name = parts.slice(2).join(' ').replace(/\s+/g, ' ').trim()
    if (!studentId) continue
    await dbEnrollStudent(courseId, studentId, name, regNo)
    imported++
  }
  const list = await (await import('./db.js')).getEnrollmentRecords(courseId)
  res.json({ courseId, imported, students: list })
})

app.delete('/courses/:courseId/enroll', async (req, res) => {
  const { courseId } = req.params
  const { studentId } = req.body || {}
  if (!studentId) return res.status(400).json({ error: 'studentId_required' })
  await dbUnenrollStudent(courseId, studentId)
  for (const [sid, sess] of sessions.entries()) {
    if (sess.courseId === courseId) sess.enrolled.delete(studentId)
  }
  return res.json({ courseId, studentId, status: 'unenrolled' })
})

// Serve frontend build (same-origin) if available
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const distPath = path.resolve(__dirname, '../dist')
if (fs.existsSync(path.join(distPath, 'index.html'))) {
  app.use(express.static(distPath))
  app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'))
  })
} else {
  // Dev mode: show a simple message on root to avoid ENOENT when dist isn't built
  app.get('/', (_req, res) => {
    res.status(200).send('Backend API running on 3001. Use the frontend at http://localhost:5174 during development.')
  })
}

const PORT = process.env.PORT || 5174
const HOST = process.env.HOST || '0.0.0.0'
server.listen(PORT, HOST, () => console.log(`Attendance server (API + SPA) on http://${HOST}:${PORT}`))


