'use client'
import { useState, useEffect, useRef, useCallback } from 'react'
import { fetchTools, fetchToolQueries, streamChat, fetchProviders, fullHealthCheck, getKBStats, getGraphSummary, seedKB, uploadToKB, runScan, getConversations, createConversation, loadConversation, saveMessage, getSettings, updateSettings, getSandboxHealth, getThreatFeedStatus, getThreatSummary, triggerThreatPull, getTopCVEs, getExploitedCVEs, getRecentIOCs, getC2Servers, exportPDF, getElkHealth, elkSeedSampleData, getSplunkHealth, getWazuhHealth, type Tool, type ChatMessage, type Provider } from '@/lib/api'

const CAT_LABELS: Record<string,string> = {scan:'🎯 Live Scanners',intel:'🌐 Threat Intel APIs',siem:'📊 SIEM Integration',detect:'🔍 AI Detection & Analysis',rule:'🎯 Threat Hunting & Rules',framework:'🗺️ Frameworks & Compliance'}
const CAT_COLORS: Record<string,string> = {scan:'border-l-[#ff3355]',intel:'border-l-[#00f0ff]',siem:'border-l-[#00ff88]',detect:'border-l-[#a855f7]',rule:'border-l-[#ffd000]',framework:'border-l-[#ff9500]'}
const CAT_BG: Record<string,string> = {scan:'bg-gradient-to-r from-[#ff3355]/20 to-[#ff6600]/20 shadow-[0_0_15px_rgba(255,51,85,0.15)]',intel:'bg-[#00f0ff]/5',siem:'bg-[#00ff88]/5',detect:'bg-[#a855f7]/5',rule:'bg-[#ffd000]/5',framework:'bg-[#ff9500]/5'}

function detectBadges(t:string){const l=t.toLowerCase(),o:{name:string;cls:string}[]=[];const m=[{k:['threat hunt','sweep'],n:'Threat Hunt',c:'bg-cs-cyan/20 text-cs-cyan border-cs-cyan/20'},{k:['siem','splunk','elastic'],n:'SIEM',c:'bg-cs-green/20 text-cs-green border-cs-green/20'},{k:['mitre','att&ck'],n:'MITRE',c:'bg-cs-cyan/20 text-cs-cyan border-cs-cyan/20'},{k:['yara'],n:'YARA',c:'bg-cs-green/20 text-cs-green border-cs-green/20'},{k:['sigma'],n:'Sigma',c:'bg-cs-green/20 text-cs-green border-cs-green/20'},{k:['nmap'],n:'Nmap',c:'bg-cs-red/20 text-cs-red border-cs-red/20'},{k:['ssl','tls'],n:'SSL/TLS',c:'bg-cs-green/20 text-cs-green border-cs-green/20'},{k:['dns'],n:'DNS',c:'bg-cs-green/20 text-cs-green border-cs-green/20'},{k:['compliance','nist','hipaa','pci'],n:'Compliance',c:'bg-cs-orange/20 text-cs-orange border-cs-orange/20'},{k:['cve','cvss','vuln'],n:'Vuln',c:'bg-cs-orange/20 text-cs-orange border-cs-orange/20'},{k:['incident'],n:'IR',c:'bg-cs-red/20 text-cs-red border-cs-red/20'},{k:['cloud','aws','azure'],n:'Cloud',c:'bg-cs-purple/20 text-cs-purple border-cs-purple/20'}];for(const i of m){if(i.k.some(k=>l.includes(k)))o.push({name:i.n,cls:i.c})};return o.slice(0,4)}

function escHtml(s:string):string{return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function fmtMsg(t:string):string{const cb:string[]=[];let s=t.replace(/```(\w*)\n?([\s\S]*?)```/g,(_,l,c)=>{const i=cb.length;cb.push(`<div class="relative my-2 rounded-lg overflow-hidden border border-cs-border"><pre class="bg-cs-bg p-3 overflow-x-auto font-mono text-[0.8rem] leading-relaxed text-cs-cyan whitespace-pre-wrap ${l?'pt-7':''}">${l?`<span class="text-[0.55rem] text-cs-text3 bg-cs-border2 px-2 py-0.5 rounded-br font-mono uppercase absolute top-0 left-0">${escHtml(l)}</span>`:''}${escHtml(c.trim())}</pre></div>`);return `%%CB${i}%%`});const ic:string[]=[];s=s.replace(/`([^`]+)`/g,(_,c)=>{const i=ic.length;ic.push(`<code class="bg-cs-bg px-1.5 py-0.5 rounded text-cs-cyan font-mono text-[0.8rem]">${escHtml(c)}</code>`);return `%%IC${i}%%`});const lk:string[]=[];s=s.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g,(_,text,url)=>{const i=lk.length;lk.push(`<a href="${escHtml(url)}" target="_blank" rel="noopener noreferrer" class="text-cs-cyan hover:text-cs-green underline underline-offset-2">${escHtml(text)}</a>`);return `%%LK${i}%%`});s=escHtml(s);cb.forEach((b,i)=>{s=s.replace(`%%CB${i}%%`,b)});ic.forEach((c,i)=>{s=s.replace(`%%IC${i}%%`,c)});lk.forEach((l,i)=>{s=s.replace(`%%LK${i}%%`,l)});return s.replace(/\*\*(.+?)\*\*/g,'<strong class="text-white/90 font-semibold">$1</strong>').replace(/\n/g,'<br/>')}

export default function Dashboard(){
  const [tools,setTools]=useState<Tool[]>([])
  const [activeTool,setActiveTool]=useState<string|null>(null)
  const [queries,setQueries]=useState<string[]>([])
  const [msgs,setMsgs]=useState<{role:string;content:string;badges?:{name:string;cls:string}[]}[]>([])
  const [hist,setHist]=useState<ChatMessage[]>([])
  const [input,setInput]=useState('')
  const [streaming,setStreaming]=useState(false)
  const [streamText,setStreamText]=useState('')
  const [streamTimer,setStreamTimer]=useState(0)
  const [providers,setProviders]=useState<Provider[]>([])
  const [provider,setProvider]=useState('ollama')
  const [mobSidebar,setMobSidebar]=useState(false)
  const [showSettings,setShowSettings]=useState(false)
  const [showHistory,setShowHistory]=useState(false)
  const [kbStats,setKbStats]=useState<any>(null)
  const [serviceHealth,setServiceHealth]=useState<any>(null)
  const [conversations,setConversations]=useState<any[]>([])
  const [convId,setConvId]=useState<string|null>(null)
  const [settingsForm,setSettingsForm]=useState<Record<string,string>>({})
  const [sandboxOk,setSandboxOk]=useState(false)
  const [copied,setCopied]=useState<number|null>(null)
  const [uploading,setUploading]=useState(false)
  const [threatData,setThreatData]=useState<any>(null)
  const [threatSummary,setThreatSummary]=useState<any>(null)
  const [showScan,setShowScan]=useState(false)
  const [scanTarget,setScanTarget]=useState('')
  const [scanType,setScanType]=useState('ping')
  const [scanning,setScanning]=useState(false)
  const [scanTimer,setScanTimer]=useState(0)
  const [cveDetail,setCveDetail]=useState<any>(null)
  const [threatPanel,setThreatPanel]=useState<string|null>(null)
  const [threatPanelData,setThreatPanelData]=useState<any[]>([])
  const [threatPanelLoading,setThreatPanelLoading]=useState(false)
  const threatCacheRef=useRef<Record<string,any[]>>({})

  const [elkOk,setElkOk]=useState(false)
  const [splunkOk,setSplunkOk]=useState(false)
  const [wazuhOk,setWazuhOk]=useState(false)
  const chatEnd=useRef<HTMLDivElement>(null)
  const abortRef=useRef(false)
  const abortCtrlRef=useRef<AbortController|null>(null)
  const genRef=useRef(0)
  const fileRef=useRef<HTMLInputElement>(null)

  useEffect(()=>{
    fetchTools().then(d=>setTools(d.tools)).catch(()=>{})
    fetchProviders().then(d=>{setProviders(d.providers);setProvider(d.default)}).catch(()=>{})
    fullHealthCheck().then(setServiceHealth).catch(()=>{})
    getKBStats().then(setKbStats).catch(()=>{})
    getConversations().then(d=>setConversations(d.conversations||[])).catch(()=>{})
    getSandboxHealth().then(d=>setSandboxOk(d.status==='connected')).catch(()=>{})
    getElkHealth().then(d=>setElkOk(d.status==='connected')).catch(()=>{})
    getSplunkHealth().then(d=>setSplunkOk(d.status==='connected')).catch(()=>{})
    getWazuhHealth().then(d=>setWazuhOk(d.status==='connected'||d.status==='connected_no_auth')).catch(()=>{})
    // Load threat intel
    getThreatFeedStatus().then(setThreatData).catch(()=>{})
    getThreatSummary().then(d=>{if(d&&d.stats)setThreatSummary(d)}).catch(()=>{})
    // Poll threat intel every 30s + retry ChromaDB/health every 15s
    const ti=setInterval(()=>{
      getThreatFeedStatus().then(setThreatData).catch(()=>{})
      getThreatSummary().then(d=>{if(d&&d.stats)setThreatSummary(d)}).catch(()=>{})
    },30000)
    const svc=setInterval(()=>{
      getKBStats().then(setKbStats).catch(()=>{})
      fullHealthCheck().then(setServiceHealth).catch(()=>{})
      getSandboxHealth().then(d=>setSandboxOk(d.status==='connected')).catch(()=>{})
      getElkHealth().then(d=>setElkOk(d.status==='connected')).catch(()=>{})
      getSplunkHealth().then(d=>setSplunkOk(d.status==='connected')).catch(()=>{})
      getWazuhHealth().then(d=>setWazuhOk(d.status==='connected'||d.status==='connected_no_auth')).catch(()=>{})
    },15000)
    return ()=>{clearInterval(ti);clearInterval(svc)}
  },[])
  useEffect(()=>{chatEnd.current?.scrollIntoView({behavior:'smooth'})},[msgs])

  const pickTool=useCallback(async(n:string)=>{
    // Intercept disconnected SIEMs — show setup guide instead of running queries
    if(n==='Splunk SIEM'&&!splunkOk){
      setActiveTool(null);setQueries([])
      setMsgs(p=>[...p,{role:'assistant',content:`## 🔍 Splunk SIEM - Not Connected\n\nSplunk is not running yet. Here's how to set it up:\n\n**Step 1:** Open PowerShell and run:\n\`\`\`bash\ndocker run -d -p 8000:8000 -p 8089:8089 \\\n  -e SPLUNK_START_ARGS=--accept-license \\\n  -e SPLUNK_PASSWORD=CyberSentinel2024 \\\n  --name splunk \\\n  splunk/splunk:latest\n\`\`\`\n\n**Step 2:** Wait 2-3 minutes for Splunk to start\n\n**Step 3:** Open Splunk Web: http://localhost:8000 (admin / CyberSentinel2024)\n\n**Step 4:** The service panel will show Splunk as 🟢 **ON** once connected\n\nThen try: *"Check Splunk health"* or *"Query Splunk for failed logins"*`}])
      return
    }
    if(n==='Wazuh SIEM'&&!wazuhOk){
      setActiveTool(null);setQueries([])
      setMsgs(p=>[...p,{role:'assistant',content:`## 🛡️ Wazuh SIEM - Not Connected\n\nWazuh is not running yet. Here's how to set it up:\n\n**Step 1:** Clone the Wazuh Docker repo:\n\`\`\`bash\ngit clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0\ncd wazuh-docker/single-node\n\`\`\`\n\n**Step 2:** Start Wazuh:\n\`\`\`bash\ndocker-compose up -d\n\`\`\`\n\n**Step 3:** Wait 3-5 minutes for all services to start\n\n**Step 4:** Open Wazuh Dashboard: https://localhost (admin / SecretPassword)\n\n**Step 5:** The service panel will show Wazuh as 🟢 **ON** once connected\n\nThen try: *"Check Wazuh health"* or *"Query Wazuh alerts"*`}])
      return
    }
    setActiveTool(n);setMobSidebar(false);setQueries(await fetchToolQueries(n).catch(()=>[]))
    setTimeout(()=>chatEnd.current?.scrollIntoView({behavior:'smooth'}),100)},[splunkOk,wazuhOk])
  const copyMsg=(content:string,idx:number)=>{navigator.clipboard.writeText(content).then(()=>{setCopied(idx);setTimeout(()=>setCopied(null),2000)}).catch(()=>{})}

  const handleUpload=async(e:React.ChangeEvent<HTMLInputElement>)=>{
    const file=e.target.files?.[0]; if(!file)return
    setUploading(true)
    try{
      const r=await uploadToKB(file,'user_docs')
      setMsgs(p=>[...p,{role:'assistant',content:`📁 **File uploaded:** ${file.name}\n${r.success?`✅ Added ${r.chunks_added} chunks to knowledge base`:`❌ Error: ${r.error}`}`}])
      getKBStats().then(setKbStats).catch(()=>{})
    }catch{setMsgs(p=>[...p,{role:'assistant',content:`❌ Upload failed for ${file.name}`}])}
    setUploading(false); if(fileRef.current)fileRef.current.value=''
  }

  const handleScan=async()=>{
    if(!scanTarget.trim()||scanning)return;setScanning(true);setScanTimer(0)
    const timerInt=setInterval(()=>setScanTimer(p=>p+1),1000)
    setMsgs(p=>[...p,{role:'user',content:`🔧 Run ${scanType} scan on ${scanTarget}`}])
    try{
      const r=await runScan(scanTarget,scanType)
      const output=r.output||r.error||'No output received'
      const out=`🔧 **${scanType.toUpperCase()} Scan - ${scanTarget}**\nDuration: ${r.duration||0}s | Exit: ${r.exit_code??'?'}\n\n\`\`\`\n${output}\n\`\`\``
      setMsgs(p=>[...p,{role:'assistant',content:out,badges:[{name:scanType.toUpperCase(),cls:'bg-cs-red/20 text-cs-red border-cs-red/20'}]}])
    }catch(e:any){setMsgs(p=>[...p,{role:'assistant',content:`❌ Scan error: ${e.message}`}])}
    clearInterval(timerInt);setScanTimer(0);setScanning(false);setShowScan(false)
  }

  const send=useCallback(async(text?:string)=>{
    const t=text||input.trim();if(!t)return;setInput('')
    const lower=t.toLowerCase().trim()
    if(lower==='clear'||lower==='reset'||lower==='new'||lower==='new chat'){newChat();return}
    // Cancel any in-flight request first
    if(streaming){abortRef.current=true;abortCtrlRef.current?.abort();setStreamText('');setStreaming(false)}
    setActiveTool(null);setQueries([])
    setMsgs(p=>[...p,{role:'user',content:t}])
    setTimeout(()=>chatEnd.current?.scrollIntoView({behavior:'smooth'}),50)
    const nh=[...hist,{role:'user' as const,content:t}];setHist(nh);setStreaming(true);setStreamText('');setStreamTimer(0)
    abortRef.current=false
    const thisGen=++genRef.current
    const abortCtrl=new AbortController();abortCtrlRef.current=abortCtrl
    const tmrId=setInterval(()=>setStreamTimer(p=>p+1),1000)
    let cid=convId
    if(!cid){try{const c=await createConversation(t.slice(0,60),provider);cid=c.id;setConvId(cid)}catch{}}
    if(cid)saveMessage(cid,'user',t).catch(()=>{})
    let full=''
    try{for await(const ch of streamChat(nh,provider,undefined,abortCtrl.signal)){if(abortRef.current||genRef.current!==thisGen){full='';break}if(ch.error){full=`⚠️ **Error:** ${ch.error}`;break}if(ch.token){full+=ch.token;setStreamText(full)}if(ch.done)break}}catch(e:any){if(e.name==='AbortError'||abortRef.current||genRef.current!==thisGen){clearInterval(tmrId);setStreamTimer(0);setStreamText('');setStreaming(false);abortRef.current=false;return}full=`⚠️ **Error:** ${e.message}`}
    clearInterval(tmrId);setStreamTimer(0)
    // Discard if cancelled or superseded by newer request
    if(abortRef.current||genRef.current!==thisGen){setStreamText('');setStreaming(false);abortRef.current=false;return}
    const badges=detectBadges(t)
    setMsgs(p=>[...p,{role:'assistant',content:full,badges}]);setHist(p=>[...p,{role:'assistant',content:full}])
    setStreamText('');setStreaming(false)
    if(cid&&full)saveMessage(cid,'assistant',full,badges).catch(()=>{})
    getConversations().then(d=>setConversations(d.conversations||[])).catch(()=>{})
  },[input,streaming,hist,provider,convId])

  const loadChat=useCallback(async(id:string)=>{try{const d=await loadConversation(id);if(d?.messages){setMsgs(d.messages.map((m:any)=>({role:m.role,content:m.content,badges:m.badges})));setHist(d.messages.map((m:any)=>({role:m.role,content:m.content})));setConvId(id);setShowHistory(false)}}catch{}},[])
  const newChat=()=>{abortRef.current=true;abortCtrlRef.current?.abort();setMsgs([]);setHist([]);setConvId(null);setStreamText('');setStreaming(false);setActiveTool(null);setQueries([])}
  const exportMd=()=>{const md=msgs.map(m=>`## ${m.role==='user'?'👤 You':'🛡️ CyberSentinel'}\n\n${m.content}`).join('\n\n---\n\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([`# CyberSentinel Export\n\n${md}`],{type:'text/markdown'}));a.download=`cybersentinel-${Date.now()}.md`;a.click()}
  const exportPdf=async()=>{try{const blob=await exportPDF(msgs.map(m=>({role:m.role,content:m.content})));const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`cybersentinel-report-${Date.now()}.pdf`;a.click()}catch{/* fallback to md */exportMd()}}
  const openSettings=async()=>{setShowSettings(true);try{await getSettings();setSettingsForm({})}catch{}}
  const doSaveSettings=async()=>{const u:Record<string,string>={};Object.entries(settingsForm).forEach(([k,v])=>{if(v)u[k]=v});if(Object.keys(u).length){await updateSettings(u).catch(()=>{});fetchProviders().then(d=>{setProviders(d.providers);setProvider(d.default)}).catch(()=>{})};setShowSettings(false)}
  const onKey=(e:React.KeyboardEvent)=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send()}}
  const openThreatPanel=async(type:string)=>{
    setThreatPanel(type);setThreatPanelLoading(true)
    // Show cached data immediately if available
    const cached=threatCacheRef.current[type]
    if(cached&&cached.length>0) setThreatPanelData(cached)
    // Fallback: use sidebar data if no cache
    else if(type==='critical'&&threatSummary?.top_cves?.length>0) setThreatPanelData(threatSummary.top_cves)
    else setThreatPanelData([])

    const fetchData=async():Promise<any[]>=>{
      try{
        if(type==='critical'){const r=await getTopCVEs(15);return r.cves||[]}
        else if(type==='exploited'){const r=await getExploitedCVEs(15);return r.vulns||[]}
        else if(type==='iocs'){const r=await getRecentIOCs('ip',15);const r2=await getRecentIOCs('domain',10);return[...(r.iocs||[]),...(r2.iocs||[])]}
      }catch{}
      return[]
    }
    let data=await fetchData()
    // Only auto-retry if we have nothing to show at all
    const hasAnything=(cached&&cached.length>0)||(type==='critical'&&threatSummary?.top_cves?.length>0)
    if(data.length===0&&!hasAnything){
      for(let i=0;i<4&&data.length===0;i++){
        await new Promise(r=>setTimeout(r,10000))
        data=await fetchData()
      }
    }
    if(data.length>0){
      threatCacheRef.current[type]=data
      setThreatPanelData(data)
    }
    setThreatPanelLoading(false)
  }
  const grouped:Record<string,Tool[]>={};tools.forEach(t=>{if(!grouped[t.cat])grouped[t.cat]=[];grouped[t.cat].push(t)})
  const showWelcome=msgs.length===0&&!activeTool

  return(
    <div className="h-screen grid grid-rows-[56px_1fr] grid-cols-1 md:grid-cols-[260px_1fr] xl:grid-cols-[260px_1fr_380px]">

      {/* TOP BAR */}
      <header className="col-span-full bg-cs-bg2 border-b border-cs-border flex items-center justify-between px-4 z-10">
        <div className="flex items-center gap-3 cursor-pointer select-none" onClick={newChat}>
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cs-cyan to-cs-purple flex items-center justify-center text-sm font-extrabold text-cs-bg font-mono">CS</div>
          <div className="leading-tight">
            <div className="font-bold text-sm tracking-tight">Cyber<span className="text-cs-cyan">Sentinel</span> AI <span className="text-[0.6rem] text-cs-text3 bg-cs-bg3 px-1.5 py-0.5 rounded font-mono ml-1">33 TOOLS</span></div>
            <div className="text-[0.5rem] text-cs-text3 font-mono">powered by <span className="text-cs-cyan/70">SolventCyber.com</span></div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a href="https://solventcyber.com" target="_blank" className="text-[0.6rem] text-cs-orange font-mono font-bold hidden lg:block hover:text-cs-cyan">SOLVENTCYBER.COM</a>
          {/* AI Provider Toggle Buttons */}
          <div className="flex items-center gap-1 bg-cs-bg/60 border border-cs-border rounded-lg px-1.5 py-1">
            {[
              {id:'ollama',label:'Local AI',icon:'🔒',color:'text-yellow-400 border-yellow-400/40 bg-yellow-400/10'},
              {id:'claude',label:'Claude',icon:'🟣',color:'text-purple-400 border-purple-400/40 bg-purple-400/10'},
              {id:'openai',label:'GPT',icon:'🟢',color:'text-green-400 border-green-400/40 bg-green-400/10'},
              {id:'openrouter',label:'Router',icon:'🌐',color:'text-cyan-400 border-cyan-400/40 bg-cyan-400/10'},
            ].map(ai=>{
              const prov=providers.find(p=>p.id===ai.id)
              const isActive=provider===ai.id
              const isAvail=prov?.configured||ai.id==='ollama'
              return <button key={ai.id}
                onClick={async()=>{if(!isAvail)return;setProvider(ai.id);try{await updateSettings({ai_provider:ai.id});fullHealthCheck().then(setServiceHealth).catch(()=>{})}catch{}}}
                title={isActive?`Active: ${prov?.model||ai.id}`:isAvail?`Switch to ${ai.label}`:`${ai.label} - no API key configured`}
                className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[0.6rem] font-mono font-semibold transition-all duration-200 border ${
                  isActive
                    ? ai.color+' shadow-[0_0_8px_rgba(0,255,136,0.15)]'
                    : isAvail
                      ? 'text-cs-text3 border-cs-border hover:border-cs-cyan/40 hover:text-cs-text2 cursor-pointer'
                      : 'text-cs-text3/40 border-transparent cursor-not-allowed opacity-40'
                }`}
              >
                <span className="text-[0.7rem]">{ai.icon}</span>
                <span className="hidden sm:inline">{ai.label}</span>
                {isActive&&<span className="w-1.5 h-1.5 rounded-full bg-cs-green shadow-[0_0_4px_#00ff88] animate-pulse"/>}
              </button>
            })}
          </div>
          <button onClick={openSettings} title="Settings" className="flex items-center justify-center w-8 h-8 bg-cs-bg3 border border-cs-border text-cs-text2 rounded-lg hover:border-cs-purple hover:text-cs-purple transition-colors text-sm">⚙️</button>
          <button onClick={newChat} className="bg-gradient-to-r from-cs-cyan to-cs-purple text-cs-bg text-[0.65rem] font-bold px-3 py-1.5 rounded-lg hover:opacity-90 transition-opacity font-mono">New Session</button>
        </div>
      </header>

      {/* SIDEBAR */}
      <aside className={`bg-cs-bg2 border-r border-cs-border overflow-y-auto py-1 ${mobSidebar?'fixed inset-y-14 left-0 w-72 z-50 block shadow-xl':'hidden md:block'}`}>
        {Object.entries(grouped).map(([cat,catTools])=>(
          <div key={cat} className="mb-1">
            <div onClick={()=>cat==='scan'?setShowScan(true):undefined} className={`flex items-center justify-between mx-2 mt-2 mb-1 px-2 py-1.5 rounded-lg ${CAT_BG[cat]||''} border-l-2 ${CAT_COLORS[cat]||'border-l-cs-text3'} ${cat==='scan'?'cursor-pointer hover:scale-[1.02] transition-transform':''}`}>
              <span className="text-[0.7rem] uppercase tracking-wider font-bold text-cs-text">{CAT_LABELS[cat]||cat}</span>
              <span className="text-[0.55rem] font-mono text-cs-text3 bg-cs-bg3 px-1.5 py-0.5 rounded">{catTools.length}</span>
            </div>
            {catTools.map(tool=>(
              <div key={tool.id} onClick={()=>pickTool(tool.name)} className={`flex items-center gap-2 px-3 py-2 mx-1 rounded cursor-pointer text-[0.85rem] transition-all truncate ${activeTool===tool.name?'bg-cs-cyan/10 text-cs-cyan border-l-2 border-cs-cyan':'text-cs-text2 hover:bg-cs-bg3 hover:text-cs-text'}`}>
                <span className="font-mono text-[0.6rem] text-cs-text3 w-5 shrink-0">{String(tool.id).padStart(2,'0')}</span>
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{background:tool.color}}/>
                <span className="truncate">{tool.name}</span>
              </div>
            ))}
          </div>
        ))}
        <div className="flex items-center gap-2 px-3 py-2 mt-2 border-t border-cs-border text-[0.65rem] text-cs-text3 font-mono"><strong className="text-cs-cyan text-lg">{tools.length}</strong> tools across <strong>{Object.keys(grouped).length}</strong> categories</div>
        <div className="px-3 pb-2 text-[0.5rem] text-cs-text3 font-mono">CyberSentinel AI v2.0 | Phase 3 Agentic</div>
      </aside>

      {/* MAIN */}
      <main className="overflow-y-auto p-4 md:p-6 flex flex-col">
        <div className="flex-1 max-w-4xl mx-auto w-full">
          {showWelcome&&<div className="text-center py-10 animate-slide-in">
            <div className="text-6xl mb-4 drop-shadow-[0_0_30px_rgba(255,51,85,0.5)] cursor-pointer hover:scale-110 transition-transform" onClick={()=>setShowScan(true)} title="Open Vulnerability Scanner">🛡️</div>
            <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight mb-1">Welcome to <span className="bg-gradient-to-r from-cs-cyan to-cs-purple bg-clip-text text-transparent">CyberSentinel AI</span></h1>
            <p className="text-[0.55rem] text-cs-text3 font-mono mb-1">powered by <span className="text-cs-cyan/70">SolventCyber.com</span></p>
            <p className="text-cs-text2 mb-6 max-w-xl mx-auto text-sm">Your Agentic Security Platform. {tools.length} real tools - every scanner executes, every API is live, every result is real. <span className="text-cs-cyan font-semibold">No fakes.</span></p>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 max-w-2xl mx-auto">
              {[{icon:'🎯',title:'Full Domain Scan',desc:'Nmap + SSL + DNS + Headers - real results, not suggestions',q:'Scan solventcyber.com - run nmap, ssl check, dns recon, and http headers',scan:false},{icon:'🔍',title:'Threat Intel Lookup',desc:'Shodan + VirusTotal + AbuseIPDB + OTX on any indicator',q:'Look up 8.8.8.8 on all threat intel sources',scan:false},{icon:'📋',title:'Compliance Audit',desc:'CIS v8, FedRAMP, HIPAA, PCI-DSS, SOC 2',q:'Assess ALL compliance frameworks for access control and encryption',scan:false},{icon:'💉',title:'SQL Injection Test',desc:'Run sqlmap against a target URL with parameters',q:'Run sqlmap against http://testphp.vulnweb.com/listproducts.php?cat=1',scan:false},{icon:'💀',title:'Vuln Scan',desc:'Nuclei + Nikto - real CVE & misconfiguration detection',q:'',scan:true},{icon:'⚡',title:'Rule Generator',desc:'Multi-format detection rules in one shot',q:'Generate Sigma + YARA + Snort rules for detecting Cobalt Strike',scan:false}].map((b,i)=>(
                <button key={i} onClick={()=>b.scan?setShowScan(true):send(b.q)} className={`rounded-xl p-4 text-left transition-all hover:-translate-y-0.5 group ${b.scan?'bg-gradient-to-br from-[#ff3355]/20 to-[#ff6600]/20 border border-[#ff3355]/40 shadow-[0_0_20px_rgba(255,51,85,0.2)] hover:shadow-[0_0_30px_rgba(255,51,85,0.35)] hover:border-[#ff3355]/60':'bg-cs-bg3 border border-cs-border hover:border-cs-cyan hover:bg-cs-cyan/5'}`}>
                  <div className={`text-xl mb-1 ${b.scan?'drop-shadow-[0_0_12px_rgba(255,51,85,0.7)]':''}`}>{b.icon}</div>
                  <div className={`font-semibold text-sm mb-1 transition-colors ${b.scan?'text-[#ff3355] group-hover:text-[#ff6600]':'group-hover:text-cs-cyan'}`}>{b.title}</div>
                  <div className="text-[0.65rem] text-cs-text3 leading-relaxed">{b.desc}</div>
                </button>))}
            </div>
          </div>}

          {/* Messages */}
          {msgs.map((msg,i)=><div key={i} className="flex gap-3 my-3 animate-slide-in group/msg">
            <div className={`w-8 h-8 rounded-lg shrink-0 flex items-center justify-center text-xs font-bold ${msg.role==='user'?'bg-cs-bg3 text-cs-text2':'bg-gradient-to-br from-cs-cyan to-cs-purple text-cs-bg'}`}>{msg.role==='user'?'👤':'CS'}</div>
            <div className="bg-cs-bg3 border border-cs-border rounded-xl px-4 py-3 max-w-[85%] text-sm leading-relaxed relative">
              <div className="chat-content select-text" dangerouslySetInnerHTML={{__html:fmtMsg(msg.content)}}/>
              {msg.badges&&msg.badges.length>0&&<div className="flex gap-1.5 flex-wrap mt-2">{msg.badges.map((b,j)=><span key={j} className={`text-[0.65rem] px-2 py-0.5 rounded border font-mono font-medium ${b.cls}`}>{b.name}</span>)}</div>}
              <button onClick={()=>copyMsg(msg.content,i)} className={`absolute top-2 right-2 w-7 h-7 rounded-md border text-[0.65rem] flex items-center justify-center transition-all ${copied===i?'bg-cs-green/20 border-cs-green/30 text-cs-green':'bg-cs-bg border-cs-border text-cs-text3 hover:border-cs-cyan hover:text-cs-cyan'} ${msg.role==='assistant'?'opacity-100':'opacity-0 group-hover/msg:opacity-100'}`} title="Copy">{copied===i?'✓':'📋'}</button>
            </div>
          </div>)}

          {streaming&&<div className="flex gap-3 my-3 animate-slide-in">
            <div className="w-8 h-8 rounded-lg shrink-0 flex items-center justify-center text-xs font-bold bg-gradient-to-br from-cs-cyan to-cs-purple text-cs-bg">CS</div>
            <div className="bg-cs-bg3 border border-cs-border2 rounded-xl px-4 py-3 max-w-[85%] text-sm leading-relaxed w-full">
              {streamText?<div className="chat-content select-text" dangerouslySetInnerHTML={{__html:fmtMsg(streamText)}}/>:<div className="flex items-center gap-3">
                  <div className="flex gap-1.5 py-1"><span className="w-2 h-2 rounded-full bg-cs-cyan animate-[typing_1.4s_infinite]"/><span className="w-2 h-2 rounded-full bg-cs-cyan animate-[typing_1.4s_infinite_0.2s]"/><span className="w-2 h-2 rounded-full bg-cs-cyan animate-[typing_1.4s_infinite_0.4s]"/></div>
                  <span className="text-[0.65rem] text-cs-text3 font-mono">{streamTimer>0?`Thinking... ${streamTimer}s`:'Connecting...'}</span>
                </div>}
              {/* Always-visible progress bar while streaming */}
              <div className="mt-2 flex items-center gap-2"><div className="flex-1 h-1.5 bg-cs-bg rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-cs-cyan to-cs-purple rounded-full transition-all duration-1000 ease-out" style={{width:`${Math.min(streamTimer/90*100,95)}%`}}/></div><span className="text-[0.55rem] text-cs-text3 font-mono shrink-0">{streamTimer}s</span><button onClick={()=>{abortRef.current=true;abortCtrlRef.current?.abort();genRef.current++}} className="text-[0.55rem] text-cs-red font-mono hover:underline shrink-0">⏹ Stop</button></div>
            </div>
          </div>}

          {/* Tool Queries — at bottom near input */}
          {activeTool&&queries.length>0&&<div className="mb-2 animate-slide-in">
            <div className="flex items-center justify-between mb-3">
              <div className="text-sm font-bold text-cs-cyan">🔧 {activeTool}</div>
              <button onClick={()=>{setActiveTool(null);setQueries([])}} className="w-6 h-6 rounded border border-cs-border text-cs-text3 text-xs flex items-center justify-center hover:border-cs-red hover:text-cs-red">✕</button>
            </div>
            {queries.map((q,i)=><div key={i} className="flex items-center gap-2 my-1.5">
              <span className="font-mono text-[0.6rem] text-cs-text3 w-5 shrink-0">{String(i+1).padStart(2,'0')}</span>
              <div className="flex-1 bg-cs-bg3 border border-cs-border rounded-lg px-3 py-2 text-sm text-cs-text cursor-pointer hover:border-cs-cyan transition-all" onClick={()=>send(q)}>{q}</div>
              <button onClick={()=>send(q)} className="w-8 h-8 rounded-lg bg-cs-bg3 border border-cs-border text-cs-cyan text-sm flex items-center justify-center hover:bg-cs-cyan/10 shrink-0">→</button>
            </div>)}
          </div>}
          <div ref={chatEnd}/>
        </div>

        {/* ACTION BAR — History, Export, Upload like old dashboard */}
        <div className="max-w-4xl mx-auto w-full flex items-center gap-2 pt-1 flex-wrap">
          <button onClick={()=>setShowHistory(!showHistory)} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-cyan hover:text-cs-cyan transition-colors font-mono">📜 History</button>
          {msgs.length>0&&<button onClick={exportPdf} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-red hover:text-cs-red transition-colors font-mono">📕 Export PDF</button>}
          {msgs.length>0&&<button onClick={exportMd} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-green hover:text-cs-green transition-colors font-mono">📄 Export .md</button>}
          <button onClick={()=>fileRef.current?.click()} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-orange hover:text-cs-orange transition-colors font-mono">{uploading?'⏳ Uploading...':'📁 Upload'}</button>
          <input ref={fileRef} type="file" className="hidden" accept=".txt,.md,.csv,.json,.log,.pcap,.xml,.yaml,.yml,.pdf" onChange={handleUpload}/>
          <button onClick={openSettings} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-purple hover:text-cs-purple transition-colors font-mono">⚙️ Settings</button>
          <div className="flex-1"/>
          {/* NEW SESSION — always visible, fancy, like old dashboard */}
          <button onClick={newChat} className="flex items-center gap-1.5 bg-gradient-to-r from-cs-cyan to-cs-purple text-cs-bg text-[0.65rem] px-4 py-1.5 rounded-lg font-bold font-mono hover:opacity-90 transition-opacity shadow-[0_0_10px_rgba(0,240,255,0.15)]">✦ New Session</button>
        </div>

        {/* INPUT */}
        <div className="max-w-4xl mx-auto w-full pt-1 pb-2">
          <div className="flex gap-2 items-end">
            {sandboxOk&&<button onClick={()=>setShowScan(true)} className="w-12 h-12 rounded-xl bg-gradient-to-br from-cs-red to-cs-orange text-white flex items-center justify-center text-lg font-bold shrink-0 hover:scale-105 transition-transform shadow-[0_0_15px_rgba(255,51,85,0.25)]" title="Live Security Scan">🎯</button>}
            <textarea value={input} onChange={e=>setInput(e.target.value)} onKeyDown={onKey} placeholder={streaming?'Streaming...':'Ask CyberSentinel anything... (e.g., "Hunt for lateral movement in our Splunk")'} disabled={streaming} rows={1} className="flex-1 bg-cs-bg3 border border-cs-border text-cs-text rounded-xl px-4 py-3 text-sm outline-none resize-none min-h-[48px] max-h-[160px] focus:border-cs-cyan placeholder:text-cs-text3 disabled:opacity-50 font-sans"/>
            <button onClick={()=>send()} disabled={streaming} className="w-12 h-12 rounded-xl bg-gradient-to-br from-cs-cyan to-cs-green text-cs-bg flex items-center justify-center text-lg font-bold shrink-0 hover:scale-105 transition-transform shadow-[0_0_15px_rgba(0,240,255,0.2)] disabled:opacity-50">→</button>
          </div>
          <div className="text-[0.55rem] text-cs-text3 font-mono mt-1.5 px-1">⌘ Enter to send · {tools.length} tools · {provider==='ollama'?'🧠':provider==='claude'?'🟣':provider==='openai'?'🟢':'🌐'} {providers.find(p=>p.id===provider)?.model||provider} · {provider==='ollama'?'🔒 Local Mode':'☁️ Cloud Mode'}</div>
        </div>
      </main>

      {/* RIGHT PANEL / Live Threat Intel like old dashboard */}
      <aside className="hidden xl:block bg-gradient-to-b from-cs-bg2 to-[#0a0e1a] border-l border-cs-border overflow-y-auto p-4">
        {/* Arsenal Stats */}
        <div className="mb-4"><div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Arsenal Stats</div>
          <div className="grid grid-cols-2 gap-2">{[{n:'33',l:'TOOLS',c:'text-cs-cyan',bc:'border-cs-cyan/20'},{n:'6',l:'CATEGORIES',c:'text-cs-purple',bc:'border-cs-purple/20'},{n:'11',l:'SCANNERS',c:'text-cs-green',bc:'border-cs-green/20'},{n:'5',l:'INTEL APIS',c:'text-cs-orange',bc:'border-cs-orange/20'}].map((s,i)=><div key={i} className={`bg-cs-bg3 border ${s.bc} rounded-lg p-3 text-center`}><div className={`text-xl font-extrabold font-mono ${s.c}`}>{s.n}</div><div className="text-[0.5rem] text-cs-text3 uppercase tracking-wider mt-0.5">{s.l}</div></div>)}</div>
        </div>

        {/* Recent Activity */}
        <div className="mb-4"><div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Recent Activity</div>
          <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg p-3 space-y-2 text-[0.7rem]">
            {threatSummary?<>
              <div className="flex items-start gap-2"><span className="w-1.5 h-1.5 rounded-full bg-cs-red mt-1 shrink-0"/><span className="text-cs-text2 flex-1">Threat Intel: {threatSummary.stats?.total_cves||0} CVEs, {threatSummary.stats?.total_iocs||0} IOCs loaded</span><span className="text-cs-text3 text-[0.5rem]">now</span></div>
              <div className="flex items-start gap-2"><span className="w-1.5 h-1.5 rounded-full bg-cs-green mt-1 shrink-0"/><span className="text-cs-text2 flex-1">System initialized - {tools.length} tools loaded</span><span className="text-cs-text3 text-[0.5rem]">now</span></div>
              <div className="flex items-start gap-2"><span className="w-1.5 h-1.5 rounded-full bg-cs-cyan mt-1 shrink-0"/><span className="text-cs-text2 flex-1">Ollama model connected</span><span className="text-cs-text3 text-[0.5rem]">1m</span></div>
              <div className="flex items-start gap-2"><span className="w-1.5 h-1.5 rounded-full bg-cs-orange mt-1 shrink-0"/><span className="text-cs-text2 flex-1">Threat intel feeds ready</span><span className="text-cs-text3 text-[0.5rem]">2m</span></div>
              <div className="flex items-start gap-2"><span className="w-1.5 h-1.5 rounded-full bg-cs-purple mt-1 shrink-0"/><span className="text-cs-text2 flex-1">MITRE ATT&CK v14 loaded (54 techniques)</span><span className="text-cs-text3 text-[0.5rem]">2m</span></div>
            </>:<>
              <div className="flex items-start gap-2"><span className="w-1.5 h-1.5 rounded-full bg-cs-orange mt-1 shrink-0 animate-pulse"/><span className="text-cs-text2 flex-1">Pulling live threat intel...</span><span className="text-cs-text3 text-[0.5rem]">now</span></div>
              <div className="flex items-start gap-2"><span className="w-1.5 h-1.5 rounded-full bg-cs-green mt-1 shrink-0"/><span className="text-cs-text2 flex-1">System initialized - {tools.length} tools loaded</span><span className="text-cs-text3 text-[0.5rem]">now</span></div>
            </>}
          </div>
        </div>

        {/* LIVE THREAT INTEL — the big feature from old dashboard */}
        <div className="mb-4"><div className="flex items-center justify-between mb-2"><div className="text-[0.75rem] uppercase tracking-widest text-cs-text3 font-semibold">/ Live Threat Intel</div><button onClick={()=>triggerThreatPull().then(()=>{setTimeout(()=>{getThreatFeedStatus().then(setThreatData);getThreatSummary().then(d=>{if(d?.stats)setThreatSummary(d)})},10000)})} className="text-[0.6rem] bg-cs-red/20 text-cs-red px-2.5 py-1 rounded font-mono hover:bg-cs-red/30">Refresh</button></div>
          {threatSummary?.stats?<>
            {/* Stats bar — CLICKABLE */}
            <div className="grid grid-cols-3 gap-1.5 mb-3">{[{n:threatSummary.stats.critical_cves||0,l:'CRITICAL',c:'text-cs-red',bc:'hover:border-cs-red/50',t:'critical'},{n:threatSummary.stats.exploited_cves||0,l:'EXPLOITED',c:'text-cs-orange',bc:'hover:border-cs-orange/50',t:'exploited'},{n:threatSummary.stats.total_iocs||0,l:'IOCs',c:'text-cs-cyan',bc:'hover:border-cs-cyan/50',t:'iocs'}].map((s,i)=><div key={i} onClick={()=>openThreatPanel(s.t)} className={`bg-cs-bg3 border border-cs-border/30 rounded-lg p-2.5 text-center cursor-pointer transition-all ${s.bc} hover:scale-[1.02]`}><div className={`text-xl font-extrabold font-mono ${s.c}`}>{s.n}</div><div className="text-[0.55rem] text-cs-text3 uppercase tracking-wider">{s.l}</div></div>)}</div>
            <div className="text-[0.6rem] text-cs-text3 font-mono mb-2">Updated {threatSummary.generated_at?.slice(0,16).replace('T',' ')}</div>

            {/* Top CVEs — click for detail popup */}
            <div className="space-y-1.5 mb-3">{(threatSummary.top_cves||[]).slice(0,5).map((c:any,i:number)=><div key={i} onClick={()=>setCveDetail(c)} className="block bg-cs-bg border border-cs-border/30 rounded-lg p-2.5 hover:border-cs-red/50 transition-colors cursor-pointer">
              <div className="flex items-center justify-between"><span className="text-cs-red font-mono text-[0.7rem] font-bold hover:underline">{c.cve_id}</span><span className={`text-[0.6rem] font-mono px-1.5 py-0.5 rounded font-bold ${c.cvss_score>=9?'bg-cs-red/20 text-cs-red':c.cvss_score>=7?'bg-cs-orange/20 text-cs-orange':'bg-cs-cyan/20 text-cs-cyan'}`}>{c.cvss_score}</span></div>
              <div className="text-[0.65rem] text-cs-text3 mt-1 line-clamp-2 leading-relaxed">{c.description?.slice(0,120)}...</div>
            </div>)}</div>

            {/* Feed counts */}
            {threatSummary.feed_status&&<div className="space-y-1.5 mb-3">{threatSummary.feed_status.map((f:any,i:number)=><div key={i} className="flex items-center justify-between text-[0.75rem]"><span className="text-cs-text2 font-mono">{f.feed}</span><span className={`font-mono font-bold ${f.status==='success'?'text-cs-green':'text-cs-red'}`}>{f.records}</span></div>)}</div>}
          </>:<div className="bg-cs-bg3 border border-cs-border/50 rounded-lg p-4 text-center"><div className="text-cs-orange text-sm animate-pulse mb-1">⏳</div><div className="text-[0.7rem] text-cs-text3">Pulling live threat intel...</div><div className="text-[0.6rem] text-cs-text3 mt-1">NVD, CISA KEV, EPSS, OTX, Abuse.ch</div></div>}
        </div>

        {/* Services */}
        <div className="mb-4"><div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Services</div>
          <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg p-3 space-y-2">
            {[
              {name:'Local AI (Ollama)',icon:'🔒',id:'ollama',ok:serviceHealth?.services?.ollama?.status==='connected',sub:serviceHealth?.services?.ollama?.status==='connected'?(providers.find(p=>p.id==='ollama')?.model||'qwen2.5:7b'):''},
              {name:'Neo4j Graph',icon:'🕸️',id:'neo4j',ok:serviceHealth?.services?.neo4j?.status==='connected',sub:''},
              {name:'ChromaDB RAG',icon:'📚',id:'chromadb',ok:kbStats?.status==='connected',sub:''},
              {name:'Kali Sandbox',icon:'🐧',id:'sandbox',ok:sandboxOk,sub:''},
              {name:'ELK Stack',icon:'📊',id:'elk',ok:elkOk,sub:''},
              {name:'Splunk',icon:'🔍',id:'splunk',ok:splunkOk,sub:''},
              {name:'Wazuh',icon:'🛡️',id:'wazuh',ok:wazuhOk,sub:''},
              {name:'Claude API',icon:'🟣',id:'claude',ok:serviceHealth?.services?.claude?.configured,sub:provider==='claude'?(providers.find(p=>p.id==='claude')?.model||''):''},
              {name:'OpenAI API',icon:'🟢',id:'openai',ok:serviceHealth?.services?.openai?.configured,sub:provider==='openai'?(providers.find(p=>p.id==='openai')?.model||''):''},
              {name:'OpenRouter',icon:'🌐',id:'openrouter',ok:serviceHealth?.services?.openrouter?.configured||!!providers.find(p=>p.id==='openrouter'&&p.configured),sub:provider==='openrouter'?(providers.find(p=>p.id==='openrouter')?.model||''):''},
            ].map((s,i)=>{
              const isAI=['ollama','claude','openai','openrouter'].includes(s.id)
              const isActive=isAI&&provider===s.id
              return <div key={i}>
                <div className={`flex items-center justify-between text-[0.75rem] ${isActive?'bg-cs-cyan/5 -mx-1 px-1 rounded':''}`}>
                  <span className="text-cs-text2 flex items-center gap-1.5">
                    <span>{s.icon}</span>{s.name}
                    {isActive&&<span className="text-[0.5rem] text-cs-cyan font-mono bg-cs-cyan/10 px-1 py-0.5 rounded">ACTIVE</span>}
                  </span>
                  <span className={`font-mono text-[0.6rem] flex items-center gap-1 px-2 py-0.5 rounded-full ${s.ok?'text-cs-green bg-cs-green/10':'text-cs-red bg-cs-red/10'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${s.ok?'bg-cs-green shadow-[0_0_4px_#00ff88]':'bg-cs-red'}`}/>
                    {s.ok?'ON':'OFF'}
                  </span>
                </div>
                {s.sub&&<div className="ml-7 text-[0.6rem] text-cs-green font-mono mt-0.5">{s.sub}</div>}
              </div>
            })}
            {elkOk&&<button onClick={async(e)=>{const btn=e.currentTarget;btn.textContent='⏳ Seeding...';btn.disabled=true;try{const r=await elkSeedSampleData();btn.textContent=`✅ ${r.message||'Seeded!'}`}catch{btn.textContent='❌ Failed'}setTimeout(()=>{btn.textContent='📊 Seed ELK with 500+ Security Events';btn.disabled=false},3000)}} className="w-full mt-1 bg-gradient-to-r from-cs-green/20 to-cs-cyan/20 border border-cs-green/30 text-cs-green text-[0.55rem] py-1.5 rounded-lg font-mono hover:from-cs-green/30 hover:to-cs-cyan/30 disabled:opacity-50">📊 Seed ELK with 500+ Security Events</button>}
          </div>
        </div>

        {/* Knowledge Base */}
        <div className="mb-4"><div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Knowledge Base</div>
          <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg p-3">
            {kbStats?.status==='connected'?<div className="space-y-1.5">{Object.entries(kbStats.collections||{}).filter(([n,info]:any)=>info.documents>0).map(([n,info]:any)=><div key={n} className="flex items-center justify-between text-[0.7rem]"><span className="text-cs-text2 truncate capitalize">{n.replace(/_/g,' ')}</span><span className="text-cs-cyan font-mono text-[0.55rem] bg-cs-cyan/10 px-1.5 py-0.5 rounded">{info.documents}</span></div>)}{Object.values(kbStats.collections||{}).every((c:any)=>c.documents===0)&&<div className="text-cs-text3 text-[0.65rem] text-center py-1">No documents yet</div>}<button onClick={()=>seedKB().then(()=>getKBStats().then(setKbStats))} className="mt-2 w-full bg-gradient-to-r from-cs-purple/20 to-cs-cyan/20 border border-cs-purple/30 text-cs-purple text-[0.6rem] py-1.5 rounded-lg font-mono hover:from-cs-purple/30 hover:to-cs-cyan/30">🧠 Seed Knowledge</button></div>:<div className="text-cs-text3 text-[0.7rem] text-center py-2">Connecting to ChromaDB...</div>}
          </div>
        </div>

        {/* Creator */}
        <div><div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Creator</div>
          <div className="bg-gradient-to-br from-cs-orange/10 to-cs-purple/10 border border-cs-orange/20 rounded-lg p-3 text-center">
            <a href="https://www.credly.com/users/eskintan/badges#credly" target="_blank" className="font-bold text-cs-orange text-sm hover:text-cs-cyan transition-colors">🏅 3sk1nt4n</a>
            <div className="text-[0.5rem] text-cs-text3 font-mono mt-1">CyberSentinel AI v2.0 Phase 3 | Agentic</div>
          </div>
        </div>
      </aside>

      {/* HISTORY */}
      {showHistory&&<div className="fixed inset-0 bg-black/60 z-50 flex" onClick={()=>setShowHistory(false)}>
        <div className="w-80 bg-cs-bg2 border-r border-cs-border h-full overflow-y-auto p-4" onClick={e=>e.stopPropagation()}>
          <div className="flex items-center justify-between mb-4"><h2 className="text-sm font-bold">📜 Chat History</h2><button onClick={()=>setShowHistory(false)} className="text-cs-text3 hover:text-cs-red text-sm">✕</button></div>
          <button onClick={()=>{newChat();setShowHistory(false)}} className="w-full bg-cs-cyan/10 border border-cs-cyan/20 text-cs-cyan text-xs py-2 rounded-lg mb-3 hover:bg-cs-cyan/20">+ New Chat</button>
          {conversations.length===0?<div className="text-cs-text3 text-xs text-center py-4">No conversations yet</div>:conversations.map((c:any)=><div key={c.id} className="bg-cs-bg3 border border-cs-border rounded-lg p-3 mb-2 cursor-pointer hover:border-cs-cyan transition-colors" onClick={()=>loadChat(c.id)}><div className="text-sm text-cs-text truncate">{c.title}</div><div className="text-[0.6rem] text-cs-text3 font-mono mt-1">{c.message_count} msgs · {c.provider}</div></div>)}
        </div>
      </div>}

      {/* SETTINGS */}
      {showSettings&&<div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={()=>setShowSettings(false)}>
        <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-lg max-h-[80vh] overflow-y-auto p-6" onClick={e=>e.stopPropagation()}>
          <div className="flex items-center justify-between mb-4"><h2 className="text-lg font-bold">⚙️ Settings</h2><button onClick={()=>setShowSettings(false)} className="text-cs-text3 hover:text-cs-red">✕</button></div>
          {[{k:'anthropic_api_key',l:'Anthropic API Key',p:'sk-ant-...'},{k:'openai_api_key',l:'OpenAI API Key',p:'sk-...'},{k:'openrouter_api_key',l:'OpenRouter API Key',p:'sk-or-...'},{k:'shodan_api_key',l:'Shodan API Key',p:'Shodan key'},{k:'virustotal_api_key',l:'VirusTotal API Key',p:'VT key'},{k:'otx_api_key',l:'AlienVault OTX Key',p:'OTX key'},{k:'abuseipdb_api_key',l:'AbuseIPDB API Key',p:'AbuseIPDB key'},{k:'censys_api_id',l:'Censys API ID',p:'Censys ID'}].map(({k,l,p})=><div key={k} className="mb-3"><label className="text-xs text-cs-text2 mb-1 block">{l}</label><input type="password" placeholder={p} value={settingsForm[k]||''} onChange={e=>setSettingsForm(f=>({...f,[k]:e.target.value}))} className="w-full bg-cs-bg3 border border-cs-border text-cs-text rounded-lg px-3 py-2 text-sm font-mono outline-none focus:border-cs-cyan"/></div>)}
          <div className="flex gap-2 mt-4"><button onClick={doSaveSettings} className="flex-1 bg-cs-cyan/20 border border-cs-cyan/30 text-cs-cyan py-2 rounded-lg text-sm font-semibold hover:bg-cs-cyan/30">Save</button><button onClick={()=>setShowSettings(false)} className="flex-1 bg-cs-bg3 border border-cs-border text-cs-text2 py-2 rounded-lg text-sm hover:border-cs-red">Cancel</button></div>
        </div>
      </div>}

      {/* THREAT DETAIL PANEL */}
      {threatPanel&&<div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={()=>setThreatPanel(null)}>
        <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-2xl p-6 max-h-[85vh] overflow-y-auto" onClick={e=>e.stopPropagation()}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold">{threatPanel==='critical'?'🔴 Critical CVEs (CVSS ≥ 9.0)':threatPanel==='exploited'?'🟠 CISA KEV - Actively Exploited':'🔵 Indicators of Compromise (IOCs)'}</h2>
            <button onClick={()=>setThreatPanel(null)} className="text-cs-text3 hover:text-cs-red text-lg">✕</button>
          </div>
          <div className="text-[0.65rem] text-cs-text3 mb-4 leading-relaxed">{threatPanel==='critical'?'These are the highest severity vulnerabilities (CVSS 9.0-10.0) recently published. They represent the most dangerous flaws: remote code execution, authentication bypass, and full system compromise. Patch these IMMEDIATELY.':threatPanel==='exploited'?'CISA Known Exploited Vulnerabilities (KEV) catalog - these are confirmed actively exploited in the wild by threat actors. Federal agencies have mandatory remediation deadlines. If you have these, you are likely being targeted NOW.':'Indicators of Compromise from Abuse.ch and AlienVault OTX threat feeds. These IPs, domains, and hashes are associated with active malware campaigns, C2 infrastructure, and botnet operations.'}</div>
          {threatPanelLoading&&threatPanelData.length===0?<div className="text-center py-8"><div className="text-2xl mb-2 animate-pulse">⏳</div><div className="text-sm text-cs-text3">Loading...</div><div className="text-[0.6rem] text-cs-text3 mt-2">Auto-retrying if feeds are still loading</div></div>:
          threatPanelData.length===0?<div className="text-center py-8"><div className="text-2xl mb-2">📭</div><div className="text-sm text-cs-text3">No data available.</div><div className="text-[0.65rem] text-cs-text3 mt-2">Threat intel feeds may not have finished pulling. Click <strong>Refresh</strong> in the Live Threat Intel panel and try again in a minute.</div></div>:
          threatPanel==='critical'?<div className="space-y-2">{threatPanelData.map((c:any,i:number)=><div key={i} onClick={()=>{setThreatPanel(null);setCveDetail(c)}} className="bg-cs-bg border border-cs-border/30 rounded-lg p-3 hover:border-cs-red/50 cursor-pointer transition-all">
            <div className="flex items-center justify-between mb-1"><span className="text-cs-red font-mono text-sm font-bold">{c.cve_id}</span><div className="flex gap-2"><span className={`text-[0.6rem] font-mono px-2 py-0.5 rounded font-bold ${c.cvss_score>=9.5?'bg-cs-red/20 text-cs-red':'bg-cs-orange/20 text-cs-orange'}`}>CVSS {c.cvss_score}</span>{c.epss_score>0&&<span className="text-[0.6rem] font-mono px-2 py-0.5 rounded bg-cs-purple/20 text-cs-purple">EPSS {(c.epss_score*100).toFixed(1)}%</span>}{c.actively_exploited?<span className="text-[0.6rem] font-mono px-2 py-0.5 rounded bg-cs-red/30 text-cs-red">⚠️ EXPLOITED</span>:null}</div></div>
            {c.vendor&&<div className="text-[0.6rem] text-cs-cyan font-mono mb-1">{c.vendor} | {c.product}</div>}
            <div className="text-[0.65rem] text-cs-text2 leading-relaxed">{c.description?.slice(0,200)}{c.description?.length>200?'...':''}</div>
          </div>)}</div>:
          threatPanel==='exploited'?<div className="space-y-2">{threatPanelData.map((v:any,i:number)=><div key={i} className="bg-cs-bg border border-cs-border/30 rounded-lg p-3 hover:border-cs-orange/50 transition-all">
            <div className="flex items-center justify-between mb-1"><a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" className="text-cs-orange font-mono text-sm font-bold hover:underline">{v.cve_id}</a><div className="flex gap-2">{v.known_ransomware==='Known'&&<span className="text-[0.6rem] font-mono px-2 py-0.5 rounded bg-cs-red/30 text-cs-red">💀 RANSOMWARE</span>}<span className="text-[0.6rem] font-mono px-2 py-0.5 rounded bg-cs-orange/10 text-cs-orange">Due: {v.due_date?.slice(0,10)}</span></div></div>
            <div className="text-[0.65rem] text-cs-cyan font-mono mb-1">{v.vendor} | {v.product}</div>
            <div className="text-[0.65rem] text-cs-text2">{v.name}</div>
            <div className="text-[0.5rem] text-cs-text3 mt-1">Added to KEV: {v.date_added?.slice(0,10)}</div>
          </div>)}</div>:
          <div className="space-y-2">{threatPanelData.map((ioc:any,i:number)=><div key={i} className="bg-cs-bg border border-cs-border/30 rounded-lg p-3 hover:border-cs-cyan/50 transition-all">
            <div className="flex items-center justify-between mb-1"><a href={ioc.indicator?.includes('.')?`https://www.abuseipdb.com/check/${ioc.indicator}`:undefined} target="_blank" className="text-cs-cyan font-mono text-sm font-bold hover:underline">{ioc.indicator}</a><span className={`text-[0.6rem] font-mono px-2 py-0.5 rounded ${ioc.confidence>=80?'bg-cs-red/20 text-cs-red':ioc.confidence>=50?'bg-cs-orange/20 text-cs-orange':'bg-cs-cyan/20 text-cs-cyan'}`}>{ioc.confidence||'?'}% conf</span></div>
            <div className="flex gap-2 flex-wrap">{ioc.threat_type&&<span className="text-[0.55rem] font-mono px-1.5 py-0.5 rounded bg-cs-red/10 text-cs-red">{ioc.threat_type}</span>}{ioc.malware_family&&<span className="text-[0.55rem] font-mono px-1.5 py-0.5 rounded bg-cs-purple/10 text-cs-purple">{ioc.malware_family}</span>}<span className="text-[0.55rem] font-mono px-1.5 py-0.5 rounded bg-cs-bg3 text-cs-text3">{ioc.source}</span></div>
            {ioc.first_seen&&<div className="text-[0.5rem] text-cs-text3 mt-1">First seen: {ioc.first_seen?.slice(0,16)}</div>}
          </div>)}</div>}
          <div className="mt-4 pt-3 border-t border-cs-border text-[0.55rem] text-cs-text3 font-mono text-center">Data from NVD, CISA KEV, EPSS, Abuse.ch, AlienVault OTX</div>
        </div>
      </div>}

      {/* CVE DETAIL MODAL */}
      {cveDetail&&<div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={()=>setCveDetail(null)}>
        <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-lg p-6 max-h-[80vh] overflow-y-auto" onClick={e=>e.stopPropagation()}>
          <div className="flex items-center justify-between mb-4"><h2 className="text-lg font-bold text-cs-red font-mono">{cveDetail.cve_id}</h2><button onClick={()=>setCveDetail(null)} className="text-cs-text3 hover:text-cs-red">✕</button></div>
          <div className="flex gap-2 mb-4">
            <span className={`text-sm font-mono px-2 py-1 rounded font-bold ${cveDetail.cvss_score>=9?'bg-cs-red/20 text-cs-red':cveDetail.cvss_score>=7?'bg-cs-orange/20 text-cs-orange':'bg-cs-cyan/20 text-cs-cyan'}`}>CVSS {cveDetail.cvss_score}</span>
            <span className={`text-sm font-mono px-2 py-1 rounded ${cveDetail.cvss_score>=9?'bg-cs-red/10 text-cs-red':'bg-cs-orange/10 text-cs-orange'}`}>{cveDetail.cvss_score>=9?'CRITICAL':cveDetail.cvss_score>=7?'HIGH':cveDetail.cvss_score>=4?'MEDIUM':'LOW'}</span>
          </div>
          <div className="mb-4"><div className="text-xs text-cs-text3 uppercase mb-1 font-semibold">Description</div><div className="text-sm text-cs-text leading-relaxed">{cveDetail.description||'No description available.'}</div></div>
          <div className="mb-4"><div className="text-xs text-cs-text3 uppercase mb-1 font-semibold">🛡️ How to Protect</div><div className="text-sm text-cs-text2 leading-relaxed space-y-1">
            {cveDetail.cvss_score>=9?<><p>• <strong>Patch immediately</strong> - this is a critical vulnerability actively being targeted.</p><p>• Apply vendor security updates or virtual patching via WAF/IPS rules.</p><p>• Isolate affected systems until patched. Monitor for exploitation indicators.</p><p>• Check CISA KEV catalog for known exploitation status.</p></>:
            cveDetail.cvss_score>=7?<><p>• <strong>Prioritize patching</strong> within your next maintenance window.</p><p>• Apply compensating controls (network segmentation, access restrictions).</p><p>• Monitor logs for exploitation attempts targeting this CVE.</p><p>• Review vendor advisory for specific mitigation guidance.</p></>:
            <><p>• Schedule patching during normal maintenance cycles.</p><p>• Apply defense-in-depth controls as compensating measures.</p><p>• Monitor for any escalation in exploitation activity via EPSS scores.</p></>}
          </div></div>
          <div className="flex gap-2"><a href={`https://nvd.nist.gov/vuln/detail/${cveDetail.cve_id}`} target="_blank" className="flex-1 text-center bg-cs-cyan/10 border border-cs-cyan/30 text-cs-cyan py-2 rounded-lg text-sm font-mono hover:bg-cs-cyan/20">📋 NVD Detail</a><a href={`https://www.cvedetails.com/cve/${cveDetail.cve_id}`} target="_blank" className="flex-1 text-center bg-cs-orange/10 border border-cs-orange/30 text-cs-orange py-2 rounded-lg text-sm font-mono hover:bg-cs-orange/20">🔍 CVE Details</a></div>
        </div>
      </div>}

      {/* SCAN MODAL */}
      {showScan&&<div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={()=>setShowScan(false)}>
        <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-md p-6" onClick={e=>e.stopPropagation()}>
          <div className="flex items-center justify-between mb-4"><h2 className="text-lg font-bold">🎯 Live Security Scan</h2><button onClick={()=>setShowScan(false)} className="text-cs-text3 hover:text-cs-red">✕</button></div>
          <div className="mb-3"><label className="text-xs text-cs-text2 mb-1 block">Target (IP, domain, or URL)</label><input type="text" placeholder="e.g., google.com or 8.8.8.8" value={scanTarget} onChange={e=>setScanTarget(e.target.value)} className="w-full bg-cs-bg3 border border-cs-border text-cs-text rounded-lg px-3 py-2 text-sm font-mono outline-none focus:border-cs-cyan" onKeyDown={e=>{if(e.key==='Enter')handleScan()}}/></div>
          <div className="mb-3"><label className="text-xs text-cs-text2 mb-1 block">Scan Type</label>
            <div className="grid grid-cols-2 gap-2">{[{id:'ping',icon:'🏓',label:'Ping',test:'8.8.8.8'},{id:'nmap',icon:'🔍',label:'Nmap',test:'scanme.nmap.org'},{id:'dns',icon:'🌐',label:'DNS Recon',test:'google.com'},{id:'ssl',icon:'🔒',label:'SSL Check',test:'google.com'},{id:'whois',icon:'📋',label:'WHOIS',test:'google.com'},{id:'headers',icon:'📡',label:'HTTP Headers',test:'https://example.com'},{id:'traceroute',icon:'🛤️',label:'Traceroute',test:'8.8.8.8'},{id:'subfinder',icon:'🗺️',label:'Subdomains',test:'hackerone.com'},{id:'nikto',icon:'💀',label:'Nikto',test:'http://testphp.vulnweb.com'},{id:'nuclei',icon:'☢️',label:'Nuclei',test:'http://testphp.vulnweb.com'},{id:'sqlmap',icon:'💉',label:'SQLMap',test:'http://testphp.vulnweb.com/listproducts.php?cat=1'},{id:'zap',icon:'⚡',label:'OWASP ZAP',test:'http://testphp.vulnweb.com'}].map(s=><button key={s.id} onClick={()=>{setScanType(s.id);setScanTarget(s.test)}} className={`text-left px-3 py-2 rounded-lg border text-[0.7rem] font-mono transition-all ${scanType===s.id?'bg-cs-red/10 border-cs-red/30 text-cs-red':'bg-cs-bg3 border-cs-border text-cs-text2 hover:border-cs-cyan'}`}>{s.icon} {s.label}</button>)}</div>
          </div>
          <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg px-3 py-2 mb-3 flex items-center justify-between"><span className="text-[0.6rem] text-cs-text3 font-mono">Test target:</span><span className="text-[0.65rem] text-cs-cyan font-mono">{scanTarget||'select a scan type'}</span></div>
          <button onClick={handleScan} disabled={scanning||!scanTarget.trim()} className="w-full bg-gradient-to-r from-cs-red to-cs-orange text-white py-2.5 rounded-lg text-sm font-bold hover:opacity-90 disabled:opacity-50">{scanning?`⏳ Scanning... ${scanTimer}s`:'🚀 Execute Scan'}</button>
          {scanning&&<div className="mt-2"><div className="h-1.5 bg-cs-bg3 rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-cs-red to-cs-orange rounded-full transition-all duration-1000" style={{width:`${Math.min(scanTimer/120*100,95)}%`}}/></div></div>}
          <div className="text-[0.55rem] text-cs-text3 font-mono mt-2 text-center">Runs in isolated Kali sandbox container</div>
          <div className="mt-3 bg-cs-bg border border-cs-orange/20 rounded-lg p-3">
            <div className="text-[0.6rem] text-cs-orange font-bold mb-1">⚠️ Legal Notice - Educational & Authorized Use Only</div>
            <div className="text-[0.5rem] text-cs-text3 leading-relaxed">These scanning tools are provided <span className="text-cs-text2">strictly for educational purposes, authorized penetration testing, and security research</span>. By executing a scan you confirm: (1) You own the target or have <span className="text-cs-text2">explicit written authorization</span> from the owner to test it. (2) You are conducting a lawful security assessment in compliance with all applicable laws including the <span className="text-cs-text2">Computer Fraud and Abuse Act (CFAA)</span>, <span className="text-cs-text2">GDPR</span>, and local regulations. (3) You accept full responsibility for any scans executed. Unauthorized scanning of systems you do not own is <span className="text-cs-red">illegal</span> and may result in criminal prosecution. Use the provided test targets (testphp.vulnweb.com, scanme.nmap.org) for safe, legal practice.</div>
          </div>
        </div>
      </div>}

      {mobSidebar&&<div className="fixed inset-0 bg-black/50 z-40 md:hidden" onClick={()=>setMobSidebar(false)}/>}
    </div>
  )
}
