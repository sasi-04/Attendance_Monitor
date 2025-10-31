import React, { useCallback, useRef, useState } from 'react'
import StudentQrScanner from '../../components/StudentQrScanner.jsx'
import { apiPost } from '../../components/api.js'
import { useAuth } from '../../context/AuthContext.jsx'

export default function StudentScanAttendance(){
  const [scanState, setScanState] = useState({ status: 'idle', message: '' })
  const inputRef = useRef(null)
  const { user } = useAuth()

  const validateToken = async (token) => {
    try {
      setScanState({ status: 'validating', message: 'Validating…' })
      const res = await apiPost('/attendance/scan', { token, studentId: user?.studentId })
      setScanState({ status: 'success', message: `Marked present at ${new Date(res.markedAt).toLocaleTimeString()}` })
    } catch (err) {
      const code = err.code
      const msg = code === 'expired_code' ? 'QR expired. Ask staff to regenerate.'
        : code === 'already_used' ? 'Code already used.'
        : code === 'not_enrolled' ? 'You are not enrolled for this session.'
        : code === 'session_closed' ? 'Session closed.'
        : code === 'network_error' ? 'Network error. Check your connection.'
        : 'Invalid QR code.'
      setScanState({ status: 'error', message: msg })
    }
  }

  const onSubmitToken = useCallback(async (e) => {
    e.preventDefault()
    const token = inputRef.current?.value?.trim()
    if (!token) return
    inputRef.current.value = ''
    await validateToken(token)
  }, [])

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold">QR Scanner</h2>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="aspect-square bg-black/5 rounded-lg overflow-hidden flex items-center justify-center">
              {typeof navigator !== 'undefined' && navigator.mediaDevices ? (
                <StudentQrScanner
                  onDecode={(result) => validateToken(String(result))}
                  onError={() => {}}
                  constraints={{ facingMode: 'environment' }}
                />
              ) : (
                <div className="p-4 text-center text-sm text-gray-600">Camera not available in this context.</div>
              )}
            </div>
            <div className="text-sm">
              {scanState.status === 'validating' && <span className="text-gray-600">{scanState.message}</span>}
              {scanState.status === 'success' && <span className="text-green-700">{scanState.message}</span>}
              {scanState.status === 'error' && <span className="text-red-700">{scanState.message}</span>}
            </div>
          </div>
          <div>
            <form onSubmit={onSubmitToken} className="flex gap-2">
              <input ref={inputRef} placeholder="Paste scanned token" className="flex-1 px-3 py-2 rounded-md border" />
              <button type="submit" className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Validate</button>
            </form>
            <div className="mt-2 text-xs text-gray-500">If camera access is blocked, paste the token text from the QR.</div>
          </div>
        </div>
      </div>
    </div>
  )
}


