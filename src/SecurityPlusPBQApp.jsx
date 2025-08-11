import React, { useMemo, useState } from "react";

/* ---------- UI PRIMITIVES ---------- */
const Card = ({ title, children }) => (
  <div className="bg-white/70 backdrop-blur rounded-2xl shadow p-5 border border-slate-200">
    <h2 className="text-xl font-semibold mb-3 text-slate-800">{title}</h2>
    <div>{children}</div>
  </div>
);

const Pill = ({ children, tone = "slate" }) => (
  <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-${tone}-100 text-${tone}-800`}>{children}</span>
);

const Divider = () => <div className="h-px bg-slate-200 my-5" />;

const SectionHeader = ({ children }) => (
  <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-slate-900 mb-4">{children}</h1>
);

/* ---------- PBQ 1: Match control -> scenario ---------- */
const PBQ1 = ({ onScore }) => {
  const controls = ["DLP", "IPS", "SIEM", "MFA", "VPN"];
  const items = [
    { id: 1, scenario: "Prevents employees from sending unencrypted credit card numbers via email.", answer: "DLP" },
    { id: 2, scenario: "Aggregates and correlates log data from multiple systems to detect patterns.", answer: "SIEM" },
    { id: 3, scenario: "Blocks malicious traffic in real time before it reaches internal hosts.", answer: "IPS" },
    { id: 4, scenario: "Requires both a smart card and a PIN to log into a workstation.", answer: "MFA" },
    { id: 5, scenario: "Encrypts all data between a remote user and the corporate network.", answer: "VPN" },
  ];

  const [choices, setChoices] = useState(Object.fromEntries(items.map(i => [i.id, ""])));
  const [checked, setChecked] = useState(false);

  const score = useMemo(() => items.reduce((s, it) => s + (choices[it.id] === it.answer ? 1 : 0), 0), [choices]);

  const check = () => { setChecked(true); onScore?.(score, items.length); };

  return (
    <Card title="PBQ 1 – Match the security control to the scenario">
      <div className="space-y-4">
        {items.map((item) => (
          <div key={item.id} className="grid md:grid-cols-2 gap-3 items-start">
            <div className="text-slate-800">{item.scenario}</div>
            <select
              className={`w-full rounded-lg border px-3 py-2 bg-white ${checked && (choices[item.id] === item.answer ? "border-emerald-400 ring-1 ring-emerald-300" : "border-rose-300 ring-1 ring-rose-200")}`}
              value={choices[item.id]}
              onChange={(e) => setChoices({ ...choices, [item.id]: e.target.value })}
            >
              <option value="">— choose —</option>
              {controls.map((c) => (<option key={c} value={c}>{c}</option>))}
            </select>
          </div>
        ))}
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Select the best control for each scenario.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check answers</button>
      </div>
      {checked && (<div className="mt-3 text-sm"><span className="font-semibold">Score:</span> {score} / {items.length}</div>)}
    </Card>
  );
};

/* ---------- PBQ 2: Firewall rule configuration ---------- */
const PBQ2 = ({ onScore }) => {
  const [rule1, setRule1] = useState({ action: "", proto: "", port: "", src: "", dst: "" });
  const [rule2, setRule2] = useState({ action: "", proto: "", port: "", src: "", dst: "" });
  const [checked, setChecked] = useState(false);

  const isRule1Correct = useMemo(() => {
    const okAction = rule1.action.toUpperCase() === "ALLOW";
    const okProto = rule1.proto.toUpperCase() === "TCP";
    const okPort = rule1.port === "443";
    const okSrc = ["ANY", "*", "INTERNET"].includes(rule1.src.trim().toUpperCase());
    const okDst = rule1.dst.trim() === "10.10.5.25";
    return okAction && okProto && okPort && okSrc && okDst;
  }, [rule1]);

  const isRule2Correct = useMemo(() => {
    const okAction = rule2.action.toUpperCase() === "DENY";
    const okProto = ["", "TCP", "UDP"].includes(rule2.proto.toUpperCase());
    const okPort = rule2.port.trim() === ""; // deny all
    const okSrc = ["ANY", "*", "INTERNET", "0.0.0.0/0"].includes(rule2.src.trim().toUpperCase());
    const okDst = ["ANY", "*", "10.10.5.25", "0.0.0.0/0"].includes(rule2.dst.trim().toUpperCase());
    return okAction && okProto && okPort && okSrc && okDst;
  }, [rule2]);

  const check = () => {
    setChecked(true);
    const sc = (isRule1Correct ? 1 : 0) + (isRule2Correct ? 1 : 0);
    onScore?.(sc, 2);
  };

  const Field = ({ label, value, onChange, placeholder }) => (
    <label className="text-sm text-slate-700 grid gap-1">
      <span>{label}</span>
      <input className="rounded-lg border px-3 py-2" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </label>
  );

  const Select = ({ label, value, onChange, options }) => (
    <label className="text-sm text-slate-700 grid gap-1">
      <span>{label}</span>
      <select className="rounded-lg border px-3 py-2" value={value} onChange={(e)=>onChange(e.target.value)}>
        <option value=""></option>
        {options.map(o=> <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );

  return (
    <Card title="PBQ 2 – Firewall Rule Configuration">
      <p className="text-slate-700 mb-3">Allow HTTPS from the Internet to <Pill tone="emerald">10.10.5.25</Pill> and deny all other inbound connections. Put the allow rule first.</p>

      <div className="grid md:grid-cols-2 gap-4">
        <div className={`rounded-xl p-4 border ${checked ? (isRule1Correct ? "border-emerald-400" : "border-rose-300") : "border-slate-200"}`}>
          <div className="font-medium mb-2">Rule 1</div>
          <div className="grid grid-cols-2 gap-3">
            <Select label="Action" value={rule1.action} onChange={(v)=>setRule1({...rule1, action:v})} options={["ALLOW","DENY"]} />
            <Select label="Protocol" value={rule1.proto} onChange={(v)=>setRule1({...rule1, proto:v})} options={["TCP","UDP"]} />
            <Field label="Port" value={rule1.port} onChange={(v)=>setRule1({...rule1, port:v})} placeholder="443" />
            <Field label="Source" value={rule1.src} onChange={(v)=>setRule1({...rule1, src:v})} placeholder="ANY" />
            <Field label="Destination" value={rule1.dst} onChange={(v)=>setRule1({...rule1, dst:v})} placeholder="10.10.5.25" />
          </div>
        </div>

        <div className={`rounded-xl p-4 border ${checked ? (isRule2Correct ? "border-emerald-400" : "border-rose-300") : "border-slate-200"}`}>
          <div className="font-medium mb-2">Rule 2</div>
          <div className="grid grid-cols-2 gap-3">
            <Select label="Action" value={rule2.action} onChange={(v)=>setRule2({...rule2, action:v})} options={["ALLOW","DENY"]} />
            <Select label="Protocol" value={rule2.proto} onChange={(v)=>setRule2({...rule2, proto:v})} options={["TCP","UDP","(any)"]} />
            <Field label="Port" value={rule2.port} onChange={(v)=>setRule2({...rule2, port:v})} placeholder="(leave blank for any)" />
            <Field label="Source" value={rule2.src} onChange={(v)=>setRule2({...rule2, src:v})} placeholder="ANY" />
            <Field label="Destination" value={rule2.dst} onChange={(v)=>setRule2({...rule2, dst:v})} placeholder="ANY" />
          </div>
        </div>
      </div>

      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: Inbound allow for TCP/443 from ANY → 10.10.5.25, then a deny-any.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check answers</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 3: Network diagram troubleshooting ---------- */
const PBQ3 = ({ onScore }) => {
  const [device, setDevice] = useState("");
  const [rule, setRule] = useState("");
  const [checked, setChecked] = useState(false);

  const correctDevice = device === "Firewall";
  const correctRule = /allow\s+https|tcp\/?443|dmz/i.test(rule) && /from\s+internet|any/i.test(rule);

  const check = () => {
    setChecked(true);
    const sc = (correctDevice ? 1 : 0) + (correctRule ? 1 : 0);
    onScore?.(sc, 2);
  };

  return (
    <Card title="PBQ 3 – Network Diagram Troubleshooting (DMZ)">
      <pre className="text-xs md:text-sm bg-slate-900 text-slate-50 rounded-xl p-4 overflow-auto">
{`[Internet] — [Firewall] — [Switch] — [Internal Hosts]
                 \\
                  \\— [DMZ Web Server]`}
      </pre>
      <ul className="list-disc ml-6 my-3 text-slate-700 text-sm">
        <li>Internal users can browse the web fine.</li>
        <li>External customers cannot access the DMZ web server over HTTPS.</li>
        <li>Internal hosts can access the DMZ server.</li>
      </ul>
      <div className="grid md:grid-cols-2 gap-3">
        <label className="text-sm text-slate-700 grid gap-1">
          <span>Which device is most likely misconfigured?</span>
          <select className={`rounded-lg border px-3 py-2 ${checked && (correctDevice ? "border-emerald-400" : "border-rose-300")}`} value={device} onChange={(e)=>setDevice(e.target.value)}>
            <option value=""></option>
            <option>Firewall</option>
            <option>Switch</option>
            <option>DMZ Web Server</option>
          </select>
        </label>
        <label className="text-sm text-slate-700 grid gap-1">
          <span>Describe the rule to change/add (free text):</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (correctRule ? "border-emerald-400" : "border-rose-300")}`} value={rule} onChange={(e)=>setRule(e.target.value)} placeholder="e.g., Allow TCP/443 from Internet to DMZ server" />
        </label>
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: Inbound HTTPS to the DMZ likely blocked at the firewall.</div>
        <button onClick={()=>{setChecked(true); check();}} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check answers</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 4: Order of Incident Response Steps ---------- */
const PBQ4 = ({ onScore }) => {
  const correct = ["Identification", "Containment", "Eradication", "Recovery", "Lessons Learned"];
  const [steps, setSteps] = useState(["Containment","Eradication","Lessons Learned","Identification","Recovery"]);
  const [checked, setChecked] = useState(false);

  const move = (idx, dir) => {
    const next = [...steps];
    const j = idx + dir;
    if (j < 0 || j >= next.length) return;
    [next[idx], next[j]] = [next[j], next[idx]];
    setSteps(next);
  };

  const isCorrect = steps.join("|") === correct.join("|");
  const check = () => { setChecked(true); onScore?.(isCorrect ? 1 : 0, 1); };

  return (
    <Card title="PBQ 4 – Order the Incident Response Steps">
      <ol className="space-y-2">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-2">
            <button className="rounded-lg px-2 py-1 border" onClick={() => move(i, -1)}>↑</button>
            <button className="rounded-lg px-2 py-1 border" onClick={() => move(i, +1)}>↓</button>
            <span className={`flex-1 rounded-lg px-3 py-2 border ${checked ? (s === correct[i] ? "border-emerald-400" : "border-rose-300") : "border-slate-200"}`}>{i+1}. {s}</span>
          </li>
        ))}
      </ol>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: I → C → E → R → L</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check order</button>
      </div>
      {checked && (
        <div className="mt-3 text-sm">
          {isCorrect ? <span className="text-emerald-700 font-medium">Correct!</span> : <span className="text-rose-700 font-medium">Not quite—use the arrows to reorder.</span>}
        </div>
      )}
    </Card>
  );
};

/* ---------- PBQ 5: Log Analysis (WAF) ---------- */
const PBQ5 = ({ onScore }) => {
  const [a1, setA1] = useState("");
  const [a2, setA2] = useState("");
  const [a3, setA3] = useState("");
  const [checked, setChecked] = useState(false);

  const ok1 = /sql\s*injection|sqli/i.test(a1);
  const ok2 = /waf|web\s*application\s*firewall/i.test(a2);
  const ok3 = /injection/i.test(a3); // OWASP category

  const check = () => {
    setChecked(true);
    const sc = (ok1?1:0) + (ok2?1:0) + (ok3?1:0);
    onScore?.(sc, 3);
  };

  return (
    <Card title="PBQ 5 – Log Analysis (WAF)">
      <pre className="text-xs md:text-sm bg-slate-900 text-slate-50 rounded-xl p-4 overflow-auto">{`[2025-08-11 14:35:12] ALERT: SQL Injection attempt detected.
Source IP: 203.0.113.55
Target: https://secure.example.com/login
Payload: ' OR 1=1 --
Action Taken: Blocked`}</pre>
      <div className="grid md:grid-cols-3 gap-3 mt-3">
        <label className="text-sm text-slate-700 grid gap-1">
          <span>1) Attack type?</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (ok1?"border-emerald-400":"border-rose-300")}`} value={a1} onChange={(e)=>setA1(e.target.value)} placeholder="e.g., SQL injection"/>
        </label>
        <label className="text-sm text-slate-700 grid gap-1">
          <span>2) Which control stopped it?</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (ok2?"border-emerald-400":"border-rose-300")}`} value={a2} onChange={(e)=>setA2(e.target.value)} placeholder="e.g., WAF"/>
        </label>
        <label className="text-sm text-slate-700 grid gap-1">
          <span>3) OWASP Top 10 category?</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (ok3?"border-emerald-400":"border-rose-300")}`} value={a3} onChange={(e)=>setA3(e.target.value)} placeholder="e.g., Injection"/>
        </label>
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Tip: Look for keywords in the log.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check answers</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 6: ACL Order ---------- */
const PBQ6 = ({ onScore }) => {
  const [rules, setRules] = useState([
    "deny any",
    "permit tcp any 10.0.10.50 eq 22",
    "permit tcp any 10.0.10.50 eq 443",
    "permit icmp any 10.0.10.0/24",
  ]);
  const target = [
    "permit tcp any 10.0.10.50 eq 443",
    "permit tcp any 10.0.10.50 eq 22",
    "permit icmp any 10.0.10.0/24",
    "deny any",
  ];
  const [checked, setChecked] = useState(false);
  const move = (i, dir) => {
    const j = i + dir; if (j < 0 || j >= rules.length) return; const next = [...rules];
    [next[i], next[j]] = [next[j], next[i]]; setRules(next);
  };
  const isCorrect = rules.join("|") === target.join("|");
  const check = () => { setChecked(true); onScore?.(isCorrect?1:0,1); };
  return (
    <Card title="PBQ 6 – Order the ACL Rules">
      <p className="text-slate-700 mb-2">Goal: Allow HTTPS (443) and SSH (22) to 10.0.10.50, allow ICMP to 10.0.10.0/24, then deny all. Put the most specific allows first.</p>
      <ol className="space-y-2">
        {rules.map((r,i)=> (
          <li key={r} className="flex items-center gap-2">
            <button className="rounded-lg px-2 py-1 border" onClick={()=>move(i,-1)}>↑</button>
            <button className="rounded-lg px-2 py-1 border" onClick={()=>move(i,1)}>↓</button>
            <span className={`flex-1 rounded-lg px-3 py-2 border ${checked ? (r === target[i] ? 'border-emerald-400' : 'border-rose-300') : 'border-slate-200'}`}>{i+1}. {r}</span>
          </li>
        ))}
      </ol>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: Permits before catch-all deny.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check order</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 7: Wi-Fi 802.1X / WPA Choice ---------- */
const PBQ7 = ({ onScore }) => {
  const [auth, setAuth] = useState("");
  const [enc, setEnc] = useState("");
  const [checked, setChecked] = useState(false);
  const okAuth = auth === "802.1X/EAP-TLS";
  const okEnc = enc === "AES-CCMP (WPA2-Enterprise)" || enc === "AES-GCMP (WPA3-Enterprise)";
  const check = () => { setChecked(true); onScore?.((okAuth?1:0)+(okEnc?1:0),2); };
  return (
    <Card title="PBQ 7 – Configure Secure Enterprise Wi-Fi">
      <p className="text-slate-700 mb-2">Requirement: Per-user certificates, strongest encryption, enterprise authentication.</p>
      <div className="grid md:grid-cols-2 gap-3">
        <label className="text-sm grid gap-1">
          <span>Authentication method</span>
          <select className={`rounded-lg border px-3 py-2 ${checked && (okAuth? 'border-emerald-400':'border-rose-300')}`} value={auth} onChange={e=>setAuth(e.target.value)}>
            <option value=""></option>
            <option>PSK</option>
            <option>SAE (WPA3-Personal)</option>
            <option>802.1X/PEAP</option>
            <option>802.1X/EAP-TTLS</option>
            <option>802.1X/EAP-TLS</option>
          </select>
        </label>
        <label className="text-sm grid gap-1">
          <span>Encryption suite</span>
          <select className={`rounded-lg border px-3 py-2 ${checked && (okEnc? 'border-emerald-400':'border-rose-300')}`} value={enc} onChange={e=>setEnc(e.target.value)}>
            <option value=""></option>
            <option>TKIP</option>
            <option>AES-CCMP (WPA2-Enterprise)</option>
            <option>AES-GCMP (WPA3-Enterprise)</option>
          </select>
        </label>
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Best answer: 802.1X/EAP-TLS + AES-(CCMP or GCMP).</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 8: PKI Matching ---------- */
const PBQ8 = ({ onScore }) => {
  const left = [
    {k:'Root CA', v:'Self-signed, top of trust chain'},
    {k:'Intermediate CA', v:'Issues server/user certs on behalf of root'},
    {k:'OCSP', v:'Online status check of a certificate'},
    {k:'CRL', v:'List of revoked certificates'},
  ];
  const opts = [
    'Self-signed, top of trust chain',
    'Issues server/user certs on behalf of root',
    'Online status check of a certificate',
    'List of revoked certificates',
    'Key escrow service',
  ];
  const [ans, setAns] = useState({});
  const [checked, setChecked] = useState(false);
  const score = left.reduce((s,row)=> s + (ans[row.k] === row.v ? 1 : 0), 0);
  const check = () => { setChecked(true); onScore?.(score, left.length); };
  return (
    <Card title="PBQ 8 – Match PKI Terms to Definitions">
      <div className="space-y-3">
        {left.map(r=> (
          <div key={r.k} className="grid md:grid-cols-2 gap-3 items-center">
            <div className="font-medium">{r.k}</div>
            <select className={`rounded-lg border px-3 py-2 ${checked && (ans[r.k]===r.v? 'border-emerald-400':'border-rose-300')}`} value={ans[r.k]||''} onChange={e=>setAns({...ans,[r.k]:e.target.value})}>
              <option value=""></option>
              {opts.map(o=> <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
        ))}
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Remember: Root → Intermediate → End-entity. Revocation via CRL/OCSP.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 9: Subnetting Quick ---------- */
const PBQ9 = ({ onScore }) => {
  const [cidr, setCidr] = useState("192.168.50.0/26");
  const [hosts, setHosts] = useState("");
  const [bcast, setBcast] = useState("");
  const [checked, setChecked] = useState(false);

  // /26 → 64 addresses, 62 usable; broadcast .63 in first block
  const okHosts = /^62$/.test(hosts.trim());
  const okBcast = /192\.168\.50\.63/.test(bcast.trim());

  const check = () => { setChecked(true); onScore?.((okHosts?1:0)+(okBcast?1:0),2); };

  return (
    <Card title="PBQ 9 – Subnetting (Quick)">
      <div className="grid md:grid-cols-3 gap-3 items-end">
        <label className="text-sm grid gap-1">
          <span>CIDR</span>
          <input className="rounded-lg border px-3 py-2" value={cidr} onChange={e=>setCidr(e.target.value)} />
        </label>
        <label className="text-sm grid gap-1">
          <span>Usable hosts per subnet?</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (okHosts? 'border-emerald-400':'border-rose-300')}`} value={hosts} onChange={e=>setHosts(e.target.value)} placeholder="e.g., 62" />
        </label>
        <label className="text-sm grid gap-1">
          <span>Broadcast address?</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (okBcast? 'border-emerald-400':'border-rose-300')}`} value={bcast} onChange={e=>setBcast(e.target.value)} placeholder="e.g., 192.168.50.63" />
        </label>
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: /26 → block size 64 → usable = 64−2 = 62; first block .0–.63</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 10: NAT & Port Forwarding ---------- */
const PBQ10 = ({ onScore }) => {
  const [extPort, setExtPort] = useState("");
  const [intIP, setIntIP] = useState("");
  const [proto, setProto] = useState("");
  const [checked, setChecked] = useState(false);
  const ok = extPort === "8443" && /10\.0\.20\.50:443/.test(intIP) && proto.toUpperCase() === "TCP";
  const check = () => { setChecked(true); onScore?.(ok?1:0,1); };
  return (
    <Card title="PBQ 10 – NAT: Port Forward 8443 → 10.0.20.50:443">
      <p className="text-slate-700 mb-2">Create a DNAT rule: external TCP <Pill tone="emerald">8443</Pill> maps to internal <Pill tone="emerald">10.0.20.50:443</Pill>.</p>
      <div className="grid md:grid-cols-3 gap-3">
        <label className="text-sm grid gap-1">
          <span>Protocol</span>
          <select className={`rounded-lg border px-3 py-2 ${checked && (proto.toUpperCase()==='TCP'?'border-emerald-400':'border-rose-300')}`} value={proto} onChange={e=>setProto(e.target.value)}>
            <option value=""></option>
            <option>TCP</option>
            <option>UDP</option>
          </select>
        </label>
        <label className="text-sm grid gap-1">
          <span>External port</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (extPort==='8443'?'border-emerald-400':'border-rose-300')}`} value={extPort} onChange={e=>setExtPort(e.target.value)} placeholder="8443" />
        </label>
        <label className="text-sm grid gap-1">
          <span>Internal host:port</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (/10\.0\.20\.50:443/.test(intIP)?'border-emerald-400':'border-rose-300')}`} value={intIP} onChange={e=>setIntIP(e.target.value)} placeholder="10.0.20.50:443" />
        </label>
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: DNAT (port forwarding) keeps protocol, translates port/IP.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 11: VLAN – Trunk vs Access ---------- */
const PBQ11 = ({ onScore }) => {
  const [portMode, setPortMode] = useState("");
  const [vlan, setVlan] = useState("");
  const [checked, setChecked] = useState(false);
  const okMode = portMode === "Trunk";
  const okVlan = vlan === "10,20,30";
  const check = () => { setChecked(true); onScore?.((okMode?1:0)+(okVlan?1:0),2); };
  return (
    <Card title="PBQ 11 – Connect an AP Carrying VLANs 10/20/30">
      <div className="grid md:grid-cols-2 gap-3">
        <label className="text-sm grid gap-1">
          <span>Switch port mode</span>
          <select className={`rounded-lg border px-3 py-2 ${checked && (okMode?'border-emerald-400':'border-rose-300')}`} value={portMode} onChange={e=>setPortMode(e.target.value)}>
            <option value=""></option>
            <option>Access</option>
            <option>Trunk</option>
          </select>
        </label>
        <label className="text-sm grid gap-1">
          <span>Allowed VLANs (comma-separated)</span>
          <input className={`rounded-lg border px-3 py-2 ${checked && (okVlan?'border-emerald-400':'border-rose-300')}`} value={vlan} onChange={e=>setVlan(e.target.value)} placeholder="10,20,30" />
        </label>
      </div>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: AP uplinks usually on a trunk, carrying multiple VLANs.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 12: Crypto Matching ---------- */
const PBQ12 = ({ onScore }) => {
  const rows = [
    {k:'Hash', v:'One-way integrity (e.g., SHA-256)'},
    {k:'HMAC', v:'Integrity + authentication via shared key'},
    {k:'Digital Signature', v:'Integrity + non-repudiation with private key'},
    {k:'Encryption', v:'Confidentiality (symmetric or asymmetric)'},
  ];
  const opts = rows.map(r=>r.v).concat(['Key stretching (e.g., PBKDF2)']);
  const [ans, setAns] = useState({});
  const [checked, setChecked] = useState(false);
  const score = rows.reduce((s,r)=> s + (ans[r.k]===r.v?1:0), 0);
  const check = () => { setChecked(true); onScore?.(score, rows.length); };
  return (
    <Card title="PBQ 12 – Match Crypto Functions">
      {rows.map(r=> (
        <div key={r.k} className="grid md:grid-cols-2 gap-3 items-center mb-2">
          <div className="font-medium">{r.k}</div>
          <select className={`rounded-lg border px-3 py-2 ${checked && (ans[r.k]===r.v?'border-emerald-400':'border-rose-300')}`} value={ans[r.k]||''} onChange={e=>setAns({...ans,[r.k]:e.target.value})}>
            <option value=""></option>
            {opts.map(o=> <option key={o} value={o}>{o}</option>)}
          </select>
        </div>
      ))}
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Remember: Hash ≠ Encrypt; Sign = private key creates, public verifies.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 13: Access Control Models ---------- */
const PBQ13 = ({ onScore }) => {
  const rows = [
    {k:'DAC', v:'Owner controls access via ACLs'},
    {k:'MAC', v:'Labels & clearances; enforced by policy'},
    {k:'RBAC', v:'Roles grant permissions'},
    {k:'ABAC', v:'Attributes (user, resource, context) decide'},
  ];
  const opts = rows.map(r=>r.v).concat(['Rule-based firewall']);
  const [ans, setAns] = useState({});
  const [checked, setChecked] = useState(false);
  const score = rows.reduce((s,r)=> s + (ans[r.k]===r.v?1:0), 0);
  const check = () => { setChecked(true); onScore?.(score, rows.length); };
  return (
    <Card title="PBQ 13 – Match Access Control Models">
      {rows.map(r=> (
        <div key={r.k} className="grid md:grid-cols-2 gap-3 items-center mb-2">
          <div className="font-medium">{r.k}</div>
          <select className={`rounded-lg border px-3 py-2 ${checked && (ans[r.k]===r.v?'border-emerald-400':'border-rose-300')}`} value={ans[r.k]||''} onChange={e=>setAns({...ans,[r.k]:e.target.value})}>
            <option value=""></option>
            {opts.map(o=> <option key={o} value={o}>{o}</option>)}
          </select>
        </div>
      ))}
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Tip: MAC = military labels; RBAC = job roles; ABAC = policies & attributes.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 14: Cloud Shared Responsibility ---------- */
const PBQ14 = ({ onScore }) => {
  const rows = [
    {k:'IaaS – OS patching', v:'Customer'},
    {k:'PaaS – OS patching', v:'Provider'},
    {k:'SaaS – App security & platform', v:'Provider'},
    {k:'Customer data protection (all models)', v:'Customer'},
  ];
  const opts = ['Customer','Provider'];
  const [ans, setAns] = useState({});
  const [checked, setChecked] = useState(false);
  const score = rows.reduce((s,r)=> s + (ans[r.k]===r.v?1:0), 0);
  const check = () => { setChecked(true); onScore?.(score, rows.length); };
  return (
    <Card title="PBQ 14 – Cloud Shared Responsibility">
      {rows.map(r=> (
        <div key={r.k} className="grid md:grid-cols-2 gap-3 items-center mb-2">
          <div className="font-medium">{r.k}</div>
          <select className={`rounded-lg border px-3 py-2 ${checked && (ans[r.k]===r.v?'border-emerald-400':'border-rose-300')}`} value={ans[r.k]||''} onChange={e=>setAns({...ans,[r.k]:e.target.value})}>
            <option value=""></option>
            {opts.map(o=> <option key={o} value={o}>{o}</option>)}
          </select>
        </div>
      ))}
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Rule of thumb: As you go from IaaS→SaaS, provider takes on more.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 15: Risk Metrics & DR Sites ---------- */
const PBQ15 = ({ onScore }) => {
  const rows = [
    {k:'RPO', v:'Max acceptable data loss time window'},
    {k:'RTO', v:'Max acceptable downtime to restore service'},
    {k:'MTBF', v:'Average time between failures'},
    {k:'MTTR', v:'Average time to repair'},
    {k:'Hot site', v:'Near-immediate failover, fully equipped'},
    {k:'Warm site', v:'Some equipment; moderate spin-up time'},
    {k:'Cold site', v:'Space only; long spin-up time'},
  ];
  const opts = rows.map(r=>r.v).concat(['Annualized loss expectancy']);
  const [ans, setAns] = useState({});
  const [checked, setChecked] = useState(false);
  const score = rows.reduce((s,r)=> s + (ans[r.k]===r.v?1:0), 0);
  const check = () => { setChecked(true); onScore?.(score, rows.length); };
  return (
    <Card title="PBQ 15 – Risk Metrics & DR Sites">
      {rows.map(r=> (
        <div key={r.k} className="grid md:grid-cols-2 gap-3 items-center mb-2">
          <div className="font-medium">{r.k}</div>
          <select className={`rounded-lg border px-3 py-2 ${checked && (ans[r.k]===r.v?'border-emerald-400':'border-rose-300')}`} value={ans[r.k]||''} onChange={e=>setAns({...ans,[r.k]:e.target.value})}>
            <option value=""></option>
            {opts.map(o=> <option key={o} value={o}>{o}</option>)}
          </select>
        </div>
      ))}
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Remember: RPO=data window, RTO=restore time; hot{">"}warm{">"}cold.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check</button>
      </div>
    </Card>
  );
};

/* ---------- PBQ 16: SIEM Query Builder ---------- */
const PBQ16 = ({ onScore }) => {
  const [query, setQuery] = useState("");
  const correct = 'failed_logins > 5 AND source_ip = "192.168.1.50"';
  const [result, setResult] = useState("");

  return (
    <Card title="PBQ 16 – SIEM Query Builder">
      <p>Build a query to find IP <code>192.168.1.50</code> with more than 5 failed logins.</p>
      <textarea
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        className="border rounded w-full p-2 mt-2"
        rows={3}
        placeholder='failed_logins > 5 AND source_ip = "192.168.1.50"'
      />
      <button
        className="mt-2 px-3 py-1 bg-emerald-600 text-white rounded"
        onClick={() => {
          if (query.trim().toLowerCase() === correct.toLowerCase()) {
            setResult("✅ Correct");
            onScore?.(1, 1);
          } else {
            setResult("❌ Try again");
            onScore?.(0, 1);
          }
        }}
      >
        Check
      </button>
      {result && <div className="mt-2">{result}</div>}
    </Card>
  );
};

/* ---------- PBQ 17: Backup Strategies ---------- */
const PBQ17 = ({ onScore }) => {
  const [choice, setChoice] = useState("");
  const correct = "Full + Incremental"; // minimal daily backup time, acceptable restore (chain)
  const [result, setResult] = useState("");

  return (
    <Card title="PBQ 17 – Backup Strategy Selection">
      <p>You want minimal backup time daily and acceptable restore time. Which strategy is best?</p>
      <select
        value={choice}
        onChange={(e) => setChoice(e.target.value)}
        className="border rounded px-3 py-2"
      >
        <option value="">Select</option>
        <option>Full Only</option>
        <option>Full + Differential</option>
        <option>Full + Incremental</option>
      </select>
      <button
        className="ml-3 px-3 py-2 bg-emerald-600 text-white rounded"
        onClick={() => {
          if (choice === correct) {
            setResult("✅ Correct");
            onScore?.(1, 1);
          } else {
            setResult("❌ Not quite. Remember: daily speed → incrementals; fastest restore → differentials.");
            onScore?.(0, 1);
          }
        }}
      >
        Check
      </button>
      {result && <div className="mt-2 text-sm">{result}</div>}
    </Card>
  );
};

/* ---------- PBQ 18: TLS Handshake Order ---------- */
const PBQ18 = ({ onScore }) => {
  const correctOrder = [
    "ClientHello",
    "ServerHello",
    "Server Certificate",
    "Key Exchange",
    "Finished",
  ];
  const [order, setOrder] = useState([...correctOrder].sort(() => Math.random() - 0.5));
  const [checked, setChecked] = useState(false);

  const move = (i, dir) => {
    const j = i + dir; if (j < 0 || j >= order.length) return;
    const next = [...order];
    [next[i], next[j]] = [next[j], next[i]];
    setOrder(next);
  };

  const isCorrect = order.join("|") === correctOrder.join("|");

  const check = () => { setChecked(true); onScore?.(isCorrect ? 1 : 0, 1); };

  return (
    <Card title="PBQ 18 – TLS Handshake Order">
      <ol className="space-y-2">
        {order.map((s, i) => (
          <li key={s} className="flex items-center gap-2">
            <button className="rounded-lg px-2 py-1 border" onClick={() => move(i, -1)}>↑</button>
            <button className="rounded-lg px-2 py-1 border" onClick={() => move(i, +1)}>↓</button>
            <span className={`flex-1 rounded-lg px-3 py-2 border ${checked ? (s === correctOrder[i] ? "border-emerald-400" : "border-rose-300") : "border-slate-200"}`}>{i+1}. {s}</span>
          </li>
        ))}
      </ol>
      <Divider />
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600">Hint: CHello → SHello → Cert → Keys → Finished.</div>
        <button onClick={check} className="rounded-xl px-4 py-2 bg-slate-900 text-white hover:bg-slate-800">Check order</button>
      </div>
      {checked && (
        <div className="mt-3 text-sm">
          {isCorrect ? <span className="text-emerald-700 font-medium">Correct!</span> : <span className="text-rose-700 font-medium">Reorder to match the TLS sequence.</span>}
        </div>
      )}
    </Card>
  );
};

/* ---------- FLASH: Security+ Acronym Flashcards ---------- */
const FLASH_Acronyms = () => {
  const DATA = [
    // Identity & Access
    {t:'AAA', d:'Authentication, Authorization, Accounting'},
    {t:'ABAC', d:'Attribute-Based Access Control'},
    {t:'RBAC', d:'Role-Based Access Control'},
    {t:'DAC', d:'Discretionary Access Control'},
    {t:'MAC', d:'Mandatory Access Control (labels/classifications)'},
    {t:'SSO', d:'Single Sign-On'},
    {t:'IdP', d:'Identity Provider'},
    {t:'FIM', d:'File Integrity Monitoring'},
    {t:'MFA', d:'Multi-Factor Authentication'},
    {t:'PAM', d:'Privileged Access Management'},
    {t:'PoLP', d:'Principle of Least Privilege'},

    // Network & Wireless
    {t:'ACL', d:'Access Control List (network/FS permissions)'},
    {t:'NAC', d:'Network Access Control'},
    {t:'VPN', d:'Virtual Private Network'},
    {t:'IPsec', d:'Internet Protocol Security'},
    {t:'AH', d:'Authentication Header (integrity/auth; no encryption)'},
    {t:'ESP', d:'Encapsulating Security Payload (encryption + integrity)'},
    {t:'IKE', d:'Internet Key Exchange (IPsec SA negotiation)'},
    {t:'RADIUS', d:'Remote Authentication Dial-In User Service (UDP 1812/1813)'},
    {t:'TACACS+', d:'Terminal Access Controller Access-Control System Plus (TCP 49)'},
    {t:'802.1X', d:'Port-based NAC (supplicant/authenticator/RADIUS)'},
    {t:'SSID', d:'Service Set Identifier (Wi-Fi network name)'},
    {t:'PSK', d:'Pre-Shared Key (WPA2-Personal)'},
    {t:'SAE', d:'Simultaneous Authentication of Equals (WPA3-Personal)'},
    {t:'PEAP', d:'Protected EAP (EAP inside TLS tunnel)'},
    {t:'EAP-TTLS', d:'EAP Tunneled TLS (server cert; inner auth protected)'},
    {t:'EAP-TLS', d:'EAP with mutual certificate authentication'},
    {t:'WPA2', d:'AES-CCMP'},
    {t:'WPA3', d:'SAE; AES-GCMP'},
    {t:'WPAD', d:'Web Proxy Auto-Discovery (PAC)'},
    {t:'PAC', d:'Proxy Auto-Config (proxy rules script)'},

    // Crypto & PKI
    {t:'AES', d:'Advanced Encryption Standard (symmetric)'},
    {t:'CCMP', d:'Counter Mode with CBC-MAC (WPA2)'},
    {t:'GCMP', d:'Galois/Counter Mode Protocol (WPA3)'},
    {t:'RSA', d:'Rivest–Shamir–Adleman (asymmetric)'},
    {t:'ECC', d:'Elliptic Curve Cryptography'},
    {t:'DH', d:'Diffie–Hellman (key exchange)'},
    {t:'PFS', d:'Perfect Forward Secrecy'},
    {t:'HMAC', d:'Hash-Based Message Authentication Code'},
    {t:'PBKDF2/bcrypt/scrypt/Argon2', d:'Password hashing/key stretching'},
    {t:'PKI', d:'Public Key Infrastructure'},
    {t:'CA', d:'Certificate Authority'},
    {t:'CRL', d:'Certificate Revocation List'},
    {t:'OCSP', d:'Online Certificate Status Protocol'},
    {t:'CSR', d:'Certificate Signing Request'},
    {t:'X.509', d:'Certificate standard'},
    {t:'S/MIME', d:'Secure/Multipurpose Internet Mail Extensions'},
    {t:'TLS', d:'Transport Layer Security'},

    // Governance, Risk & Compliance
    {t:'GDPR', d:'EU data protection law'},
    {t:'HIPAA', d:'US health data law'},
    {t:'PCI DSS', d:'Payment card security standard'},
    {t:'PII', d:'Personally Identifiable Information'},
    {t:'PHI', d:'Protected Health Information'},
    {t:'BIA', d:'Business Impact Analysis'},
    {t:'BCP', d:'Business Continuity Plan'},
    {t:'COOP', d:'Continuity of Operations Plan'},
    {t:'IR', d:'Incident Response'},
    {t:'RPO', d:'Recovery Point Objective'},
    {t:'RTO', d:'Recovery Time Objective'},
    {t:'MTBF', d:'Mean Time Between Failures'},
    {t:'MTTR', d:'Mean Time To Repair'},
    {t:'SLA', d:'Service Level Agreement'},

    // Monitoring & Threat Intel
    {t:'SIEM', d:'Security Information & Event Management'},
    {t:'SOAR', d:'Security Orchestration, Automation, and Response'},
    {t:'EDR', d:'Endpoint Detection & Response'},
    {t:'XDR', d:'Extended Detection & Response'},
    {t:'UEBA', d:'User and Entity Behavior Analytics'},
    {t:'IoC', d:'Indicator of Compromise'},
    {t:'TTP', d:'Tactics, Techniques, and Procedures'},
    {t:'STIX', d:'Structured Threat Information Expression'},
    {t:'TAXII', d:'Trusted Automated eXchange of Indicator Information'},
    {t:'AIS', d:'Automated Indicator Sharing (CISA)'},
    {t:'CVE', d:'Common Vulnerabilities and Exposures (MITRE)'},
    {t:'NVD', d:'National Vulnerability Database (NIST)'},

    // Data Security & Storage
    {t:'DLP', d:'Data Loss Prevention'},
    {t:'FDE', d:'Full Disk Encryption'},
    {t:'SED', d:'Self-Encrypting Drive'},
    {t:'EFS', d:'Encrypting File System (Windows)'},
    {t:'RAID', d:'0/1/5/6/10'},

    // Cloud & Architecture
    {t:'IaaS', d:'Infrastructure as a Service'},
    {t:'PaaS', d:'Platform as a Service'},
    {t:'SaaS', d:'Software as a Service'},
    {t:'SASE', d:'Secure Access Service Edge'},
    {t:'CASB', d:'Cloud Access Security Broker'},
    {t:'ZTNA', d:'Zero Trust Network Access'},
    {t:'UTM', d:'Unified Threat Management'},
    {t:'WAF', d:'Web Application Firewall'},
    {t:'DMZ', d:'Demilitarized Zone'},
  ];

  const [q, setQ] = useState('');
  const [i, setI] = useState(0);
  const [show, setShow] = useState(false);
  const [shuffled, setShuffled] = useState(false);
  const filtered = useMemo(() => DATA.filter(x => (x.t+" "+x.d).toLowerCase().includes(q.toLowerCase())), [q]);
  const list = filtered.length ? filtered : [{t:'No matches', d:'Try clearing the search.'}];
  const cur = list[i % list.length];

  const shuffle = () => {
    for (let j = list.length - 1; j > 0; j--) {
      const k = Math.floor(Math.random() * (j + 1));
      [list[j], list[k]] = [list[k], list[j]];
    }
    setI(0); setShow(false); setShuffled(true);
  };

  return (
    <Card title="FLASH – Security+ Acronyms Drill">
      <div className="grid md:grid-cols-3 gap-3 items-end">
        <label className="text-sm grid gap-1 md:col-span-2">
          <span>Search acronyms</span>
          <input className="rounded-lg border px-3 py-2" placeholder="e.g., RADIUS, PKI, SASE" value={q} onChange={e=>{setQ(e.target.value); setI(0); setShow(false);}} />
        </label>
        <div className="flex gap-2">
          <button className="rounded-xl px-3 py-2 border bg-white hover:bg-slate-50" onClick={()=>{setI((i-1+list.length)%list.length); setShow(false);}}>Prev</button>
          <button className="rounded-xl px-3 py-2 border bg-white hover:bg-slate-50" onClick={()=>{setI((i+1)%list.length); setShow(false);}}>Next</button>
          <button className="rounded-xl px-3 py-2 border bg-white hover:bg-slate-50" onClick={shuffle}>Shuffle</button>
        </div>
      </div>

      <Divider />
      <div className="grid gap-3">
        <div className="rounded-2xl border p-6 text-center bg-slate-50">
          <div className="text-3xl font-bold tracking-tight">{cur.t}</div>
          <button className="mt-3 text-sm underline" onClick={()=>setShow(s=>!s)}>{show? 'Hide definition' : 'Show definition'}</button>
          {show && <div className="mt-3 text-slate-700">{cur.d}</div>}
        </div>
        <div className="text-xs text-slate-500">{list.length} terms • {shuffled ? 'Shuffled' : 'Default order'}</div>
      </div>
    </Card>
  );
};

/* ---------- APP SHELL ---------- */
export default function SecurityPlusPBQApp() {
  const [totals, setTotals] = useState({ score: 0, max: 0 });

  const updateTotals = (s, m) => setTotals(t => ({ score: t.score + s, max: t.max + m }));
  const resetTotals = () => setTotals({ score: 0, max: 0 });

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 text-slate-900 p-4 md:p-8">
      <div className="max-w-5xl mx-auto space-y-6">
        <SectionHeader>Security+ PBQ Practice (Interactive)</SectionHeader>
        <p className="text-slate-700">Work through each PBQ and click <span className="font-medium">Check</span>. Your running score appears below.</p>

        <div className="grid gap-6">
          <PBQ1 onScore={updateTotals} />
          <PBQ2 onScore={updateTotals} />
          <PBQ3 onScore={updateTotals} />
          <PBQ4 onScore={updateTotals} />
          <PBQ5 onScore={updateTotals} />
          <PBQ6 onScore={updateTotals} />
          <PBQ7 onScore={updateTotals} />
          <PBQ8 onScore={updateTotals} />
          <PBQ9 onScore={updateTotals} />
          <PBQ10 onScore={updateTotals} />
          <PBQ11 onScore={updateTotals} />
          <PBQ12 onScore={updateTotals} />
          <PBQ13 onScore={updateTotals} />
          <PBQ14 onScore={updateTotals} />
          <PBQ15 onScore={updateTotals} />
          <PBQ16 onScore={updateTotals} />
          <PBQ17 onScore={updateTotals} />
          <PBQ18 onScore={updateTotals} />
          <FLASH_Acronyms />
        </div>

        <Card title="Running Score">
          <div className="flex items-center gap-3">
            <div className="text-2xl font-bold">{totals.score} / {totals.max}</div>
            <button onClick={resetTotals} className="ml-auto rounded-xl px-3 py-2 border bg-white hover:bg-slate-50">Reset Score</button>
          </div>
          <p className="text-sm text-slate-600 mt-2">Click each PBQ’s <em>Check</em> button to add to your score.</p>
        </Card>

        <div className="text-xs text-slate-500 text-center pt-4">
          Modules: ACLs, Firewall, NAT, VLANs, 802.1X/WPA, PKI, Subnetting, Crypto, Access Models, Cloud Shared Responsibility, Risk & DR, SIEM, Backups, TLS • Good luck on that 850+ 🚀
        </div>
      </div>
    </div>
  );
}
