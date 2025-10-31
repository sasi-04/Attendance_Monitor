import React, { useState } from 'react'
import { useAuth, useRedirectByRole } from '../context/AuthContext.jsx'

export default function StaffLoginForm(){
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const redirectByRole = useRedirectByRole()

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const resp = await fetch('/api/auth/staff/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}))
        throw new Error(j?.error || 'login_failed')
      }
      const profile = await resp.json()
      login(profile)
      redirectByRole('staff')
    } catch (err) {
      setError('Invalid email or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-blue-50 flex items-center justify-center">
      <div className="w-full max-w-md bg-white p-8 rounded-lg shadow-md">
        <div className="text-center mb-6">
          <div className="text-4xl mb-2">👩‍🏫</div>
          <h1 className="text-2xl font-bold">Staff Sign In</h1>
          <p className="text-gray-600">Use your staff credentials</p>
        </div>
        <form onSubmit={onSubmit}>
          <h2 className="text-lg font-semibold mb-4">Sign In</h2>
          <div className="mb-4">
            <label className="block text-sm font-medium mb-1">Email</label>
            <input type="text" value={email} onChange={(e)=>setEmail(e.target.value)} required className="w-full px-4 py-2 border rounded bg-gray-100" />
          </div>
          <div className="mb-4">
            <label className="block text-sm font-medium mb-1">Password</label>
            <input type="password" value={password} onChange={(e)=>setPassword(e.target.value)} required className="w-full px-4 py-2 border rounded bg-gray-100" />
          </div>
          {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
          <button type="submit" disabled={loading} className="w-full bg-black text-white py-2 rounded hover:bg-gray-800 disabled:opacity-60">
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
