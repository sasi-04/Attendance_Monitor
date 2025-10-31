import React, { useEffect, useMemo, useState } from 'react'

export default function StudentTable(){
  const [query, setQuery] = useState('')
  const [list, setList] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const courseId = '21CS701'

  async function load(){
    try{
      setLoading(true); setError('')
      const r = await fetch(`/api/courses/${courseId}/enrollments`)
      const d = await r.json().catch(()=>({}))
      if(!r.ok) throw new Error(d?.error || 'load_failed')
      setList(Array.isArray(d?.students) ? d.students : [])
    }catch(e){ setError('Failed to load') }
    finally{ setLoading(false) }
  }

  useEffect(()=>{ load() },[])

  const filtered = useMemo(()=>{
    const q = query.trim().toLowerCase()
    if(!q) return list
    return list.filter(s=>
      s.studentId?.toLowerCase().includes(q) ||
      (s.regNo||'').toLowerCase().includes(q) ||
      (s.name||'').toLowerCase().includes(q)
    )
  },[list, query])

  return (
    <div className="bg-white rounded-xl shadow-sm p-5">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
        <div className="font-semibold text-lg">Enrolled Students ({courseId})</div>
        <div className="flex gap-2 items-center">
          <input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder="Search by ID/RegNo/Name" className="px-3 py-2 rounded-md border border-gray-200 bg-gray-50 w-64" />
          <button onClick={load} className="px-3 py-2 rounded-md border">Refresh</button>
        </div>
      </div>

      {error && <div className="text-red-600 text-sm mb-2">{error}</div>}
      {loading && <div className="text-sm text-gray-600 mb-2">Loading...</div>}

      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="text-gray-600">
            <tr>
              <th className="py-2 pr-4">Student ID</th>
              <th className="py-2 pr-4">Reg.No</th>
              <th className="py-2 pr-4">Name</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {filtered.map((s,i) => (
              <tr key={s.studentId || i}>
                <td className="py-2 pr-4">{s.studentId}</td>
                <td className="py-2 pr-4">{s.regNo || '-'}</td>
                <td className="py-2 pr-4">{s.name || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}


















