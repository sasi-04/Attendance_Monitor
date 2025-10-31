
import Datastore from 'nedb-promises'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
let sessionsDb, tokensDb, codesDb, presentsDb, enrollmentsDb, staffDb, studentsDb

export function initDb(){
  if (sessionsDb) return
  sessionsDb = Datastore.create({ filename: path.resolve(__dirname, 'data/sessions.db'), autoload: true })
  tokensDb   = Datastore.create({ filename: path.resolve(__dirname, 'data/tokens.db'), autoload: true })
  codesDb    = Datastore.create({ filename: path.resolve(__dirname, 'data/codes.db'), autoload: true })
  presentsDb = Datastore.create({ filename: path.resolve(__dirname, 'data/presents.db'), autoload: true })
  enrollmentsDb = Datastore.create({ filename: path.resolve(__dirname, 'data/enrollments.db'), autoload: true })
  staffDb       = Datastore.create({ filename: path.resolve(__dirname, 'data/staff.db'), autoload: true })
  studentsDb    = Datastore.create({ filename: path.resolve(__dirname, 'data/students.db'), autoload: true })
}

export function createSession(session){
  return sessionsDb.update({ id: session.id }, { $set: session }, { upsert: true })
}

export function setCurrentToken(sessionId, jti, tokenExpiresAt){
  return sessionsDb.update({ id: sessionId }, { $set: { currentTokenJti: jti, tokenExpiresAt } })
}

export function clearCurrentToken(sessionId){
  return sessionsDb.update({ id: sessionId }, { $set: { currentTokenJti: null, tokenExpiresAt: null } })
}

export function saveToken(record){
  return tokensDb.update({ jti: record.jti }, { $set: record }, { upsert: true })
}

export function deactivateToken(jti){
  return tokensDb.update({ jti }, { $set: { active: 0 } })
}

export async function getToken(jti){
  return tokensDb.findOne({ jti })
}

export function saveShortCode(code, jti){
  return codesDb.update({ code }, { $set: { code, jti } }, { upsert: true })
}

export function deleteShortCode(code){
  return codesDb.remove({ code }, { multi: false })
}

export async function getJtiByCode(code){
  const row = await codesDb.findOne({ code })
  return row?.jti
}

export function markPresent(sessionId, studentId){
  return presentsDb.update({ sessionId, studentId }, { $set: { sessionId, studentId } }, { upsert: true })
}

export async function getPresentCount(sessionId){
  return presentsDb.count({ sessionId })
}

// Enrollment management
export function enrollStudent(courseId, studentId, name, regNo){
  const doc = { courseId, studentId }
  if (typeof name === 'string' && name.trim()) doc.name = name.trim()
  if (typeof regNo === 'string' && regNo.trim()) doc.regNo = regNo.trim()
  return enrollmentsDb.update({ courseId, studentId }, { $set: doc }, { upsert: true })
}

export function unenrollStudent(courseId, studentId){
  return enrollmentsDb.remove({ courseId, studentId }, { multi: false })
}

export async function getEnrollments(courseId){
  const rows = await enrollmentsDb.find({ courseId })
  return rows.map(r => r.studentId)
}

export async function isEnrolled(courseId, studentId){
  const row = await enrollmentsDb.findOne({ courseId, studentId })
  return !!row
}

// Detailed reads and name updates
export async function getEnrollmentRecords(courseId){
  const rows = await enrollmentsDb.find({ courseId })
  return rows.map(r => ({ studentId: r.studentId, name: r.name, regNo: r.regNo }))
}

export function setEnrollmentName(courseId, studentId, name){
  return enrollmentsDb.update({ courseId, studentId }, { $set: { name } }, { upsert: false })
}

export async function clearEnrollmentNames(courseId){
  // Remove the 'name' field from all enrollments for the course
  return enrollmentsDb.update({ courseId }, { $unset: { name: true } }, { multi: true })
}

export async function clearEnrollments(courseId){
  return enrollmentsDb.remove({ courseId }, { multi: true })
}

// Staff management (demo: store password in plain text for local dev)
export async function createStaff({ id, name, email, password }){
  const doc = { id, name, email: email?.toLowerCase(), password }
  await staffDb.update({ id }, { $set: doc }, { upsert: true })
  return doc
}

export async function listStaff(){
  return staffDb.find({})
}

export async function getStaffByEmail(email){
  return staffDb.findOne({ email: String(email).toLowerCase() })
}

// Students auth store: regNo as username, password stored in plain text for local dev
export async function createStudent({ regNo, studentId, name, password }){
  const doc = { regNo: String(regNo), studentId, name, password }
  await studentsDb.update({ regNo: doc.regNo }, { $set: doc }, { upsert: true })
  return doc
}

export async function getStudentByRegNo(regNo){
  return studentsDb.findOne({ regNo: String(regNo) })
}


