'use client'

interface CveDetailModalProps {
  cve: any
  onClose: () => void
}

export default function CveDetailModal({ cve, onClose }: CveDetailModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-lg p-6 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-cs-red font-mono">{cve.cve_id}</h2>
          <button onClick={onClose} className="text-cs-text3 hover:text-cs-red">✕</button>
        </div>
        <div className="flex gap-2 mb-4">
          <span className={`text-sm font-mono px-2 py-1 rounded font-bold ${cve.cvss_score >= 9 ? 'bg-cs-red/20 text-cs-red' : cve.cvss_score >= 7 ? 'bg-cs-orange/20 text-cs-orange' : 'bg-cs-cyan/20 text-cs-cyan'}`}>
            CVSS {cve.cvss_score}
          </span>
          <span className={`text-sm font-mono px-2 py-1 rounded ${cve.cvss_score >= 9 ? 'bg-cs-red/10 text-cs-red' : cve.cvss_score >= 7 ? 'bg-cs-orange/10 text-cs-orange' : cve.cvss_score >= 4 ? 'bg-cs-cyan/10 text-cs-cyan' : 'bg-cs-green/10 text-cs-green'}`}>
            {cve.cvss_score >= 9 ? 'CRITICAL' : cve.cvss_score >= 7 ? 'HIGH' : cve.cvss_score >= 4 ? 'MEDIUM' : 'LOW'}
          </span>
        </div>
        <div className="mb-4">
          <div className="text-xs text-cs-text3 uppercase mb-1 font-semibold">Description</div>
          <div className="text-sm text-cs-text leading-relaxed">{cve.description || 'No description available.'}</div>
        </div>
        <div className="mb-4">
          <div className="text-xs text-cs-text3 uppercase mb-1 font-semibold">🛡️ How to Protect</div>
          <div className="text-sm text-cs-text2 leading-relaxed space-y-1">
            {cve.cvss_score >= 9 ? (
              <>
                <p>• <strong>Patch immediately</strong> - this is a critical vulnerability actively being targeted.</p>
                <p>• Apply vendor security updates or virtual patching via WAF/IPS rules.</p>
                <p>• Isolate affected systems until patched. Monitor for exploitation indicators.</p>
                <p>• Check CISA KEV catalog for known exploitation status.</p>
              </>
            ) : cve.cvss_score >= 7 ? (
              <>
                <p>• <strong>Prioritize patching</strong> within your next maintenance window.</p>
                <p>• Apply compensating controls (network segmentation, access restrictions).</p>
                <p>• Monitor logs for exploitation attempts targeting this CVE.</p>
                <p>• Review vendor advisory for specific mitigation guidance.</p>
              </>
            ) : (
              <>
                <p>• Schedule patching during normal maintenance cycles.</p>
                <p>• Apply defense-in-depth controls as compensating measures.</p>
                <p>• Monitor for any escalation in exploitation activity via EPSS scores.</p>
              </>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" className="flex-1 text-center bg-cs-cyan/10 border border-cs-cyan/30 text-cs-cyan py-2 rounded-lg text-sm font-mono hover:bg-cs-cyan/20">📋 NVD Detail</a>
          <a href={`https://www.cvedetails.com/cve/${cve.cve_id}`} target="_blank" className="flex-1 text-center bg-cs-orange/10 border border-cs-orange/30 text-cs-orange py-2 rounded-lg text-sm font-mono hover:bg-cs-orange/20">🔍 CVE Details</a>
        </div>
      </div>
    </div>
  )
}
