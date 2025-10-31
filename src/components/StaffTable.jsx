import React, { useEffect, useMemo, useState } from 'react'

export default function StaffTable(){
  const [query, setQuery] = useState('')
  const [list, setList] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState({ name: '', email: '', password: '' })

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const r = await fetch('/api/staff')
      const j = await r.json()
      setList(Array.isArray(j) ? j : [])
    } catch (e) {
      setError('Failed to load staff')
    } finally {
      setLoading(false)
    }
  }

  useEffect(()=>{ load() },[])

  const filtered = useMemo(()=>{
    const q = query.toLowerCase()
    return list.filter(s =>
      (s.name?.toLowerCase().includes(q) || s.email?.toLowerCase().includes(q) || s.id?.toLowerCase().includes(q))
    )
  },[query, list])

  return (
    <div className="bg-white rounded-xl shadow-md p-6">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
        <div className="text-lg font-semibold">Staff Members</div>
        <div className="flex gap-2 items-center">
          <input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder="Search id/name/email" className="px-3 py-2 rounded-md border border-gray-200 bg-gray-50 w-64" />
          <button onClick={load} className="px-3 py-2 border rounded-md">Refresh</button>
        </div>
      </div>
      <div className="bg-gray-50 border rounded-md p-3 mb-4">
        <div className="font-medium mb-2">Add Staff</div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <input value={form.name} onChange={e=>setForm({...form, name: e.target.value})} placeholder="Name" className="px-3 py-2 border rounded bg-white" />
          <input value={form.email} onChange={e=>setForm({...form, email: e.target.value})} placeholder="Email" className="px-3 py-2 border rounded bg-white" />
          <input type="password" value={form.password} onChange={e=>setForm({...form, password: e.target.value})} placeholder="Password" className="px-3 py-2 border rounded bg-white" />
        </div>
        <div className="mt-2">
          <button onClick={async()=>{
            try{
              const r = await fetch('/api/staff', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(form) })
              if(!r.ok) throw new Error('add_failed')
              setForm({ name:'', email:'', password:'' })
              load()
            }catch(e){ alert('Failed to add staff') }
          }} className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Save</button>
        </div>
        {error && <div className="text-red-600 text-sm mt-2">{error}</div>}
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm border rounded-lg">
          <thead className="text-gray-600">
            <tr>
              <th className="py-2 pr-4">ID (email)</th>
              <th className="py-2 pr-4">Name</th>
              <th className="py-2 pr-4">Email</th>
              <th className="py-2 pr-4">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {loading ? (
              <tr><td className="py-2 px-2" colSpan={4}>Loading...</td></tr>
            ) : filtered.map((s,i)=> (
              <tr key={i}>
                <td className="py-2 pr-4">{s.id || s.email}</td>
                <td className="py-2 pr-4">{s.name}</td>
                <td className="py-2 pr-4">{s.email}</td>
                <td className="py-2 pr-4 space-x-2">
                  <button className="px-2 py-1 rounded-md border text-xs" onClick={async()=>{ const p = prompt('New password'); if(!p) return; await fetch('/api/staff', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ ...s, password: p })}); load() }}>Reset Password</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

















