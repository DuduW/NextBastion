/* NextBastion AI 辅助面板（V1.8）· 四场景共用组件
   用法：NB_AI.mount(containerOrId, {scene, getHandle(), quickActions:[{label,question}]})
   依赖：页面有 TOKEN 变量与 api() 或直接 fetch */
(function(){
  const NS='nb-ai';
  const CSS=`
  .${NS}{display:flex;flex-direction:column;height:100%;min-height:0;background:var(--card,#11161d);border-left:1px solid var(--border,#232b36);font-family:var(--mono,Consolas,monospace)}
  .${NS}-head{display:flex;gap:8px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--border,#232b36)}
  .${NS}-head b{color:#4ec9b0;font-size:13px}
  .${NS}-ctx{padding:6px 14px;font-size:11px;color:#8a9199;border-bottom:1px solid var(--border,#232b36);display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .${NS}-chip{background:#1f2b38;border:1px solid #232b36;border-radius:6px;padding:1px 8px;color:#9cdcfe}
  .${NS}-body{flex:1;overflow:auto;padding:12px 14px;font-size:12.5px;line-height:1.7}
  .${NS}-b{border-radius:10px;padding:9px 12px;margin-bottom:10px;white-space:pre-wrap;word-break:break-word}
  .${NS}-bu{background:#1c2733;border:1px solid #26333f;align-self:flex-end;margin-left:15%}
  .${NS}-ba{background:#161d26;border:1px solid #232b36;margin-right:4%}
  .${NS}-think{color:#5b6773;font-size:11.5px;border-left:2px solid #2c3947;padding-left:8px;margin:4px 0;max-height:120px;overflow:auto}
  .${NS}-code{background:#0b0f14;border:1px solid #232b36;border-radius:8px;padding:8px 10px;margin:6px 0;font-size:12px;position:relative;white-space:pre-wrap;color:#d4d4d4}
  .${NS}-copy{position:absolute;top:4px;right:8px;font-size:10.5px;color:#4ec9b0;cursor:pointer}
  .${NS}-quick{display:flex;gap:6px;padding:8px 12px 4px;flex-wrap:wrap}
  .${NS}-qb{background:#1f2b38;border:1px solid #232b36;color:#9cdcfe;border-radius:7px;padding:3px 10px;font-size:11px;cursor:pointer}
  .${NS}-qb:hover{border-color:#4ec9b0;color:#4ec9b0}
  .${NS}-input{display:flex;gap:8px;padding:10px 12px;border-top:1px solid var(--border,#232b36)}
  .${NS}-input input{flex:1;background:#0b0f14;border:1px solid #232b36;border-radius:8px;padding:8px 10px;color:#d4d4d4;font-size:12px;font-family:inherit}
  .${NS}-input input:focus{outline:none;border-color:#4ec9b0}
  .${NS}-send{background:#4ec9b0;color:#06231b;border:none;border-radius:8px;padding:6px 14px;font-weight:700;cursor:pointer;font-size:12px}
  .${NS}-privacy{font-size:10.5px;color:#8a9199;padding:6px 14px;border-top:1px solid var(--border,#232b36)}
  .${NS}-guide{text-align:center;padding:36px 18px;color:#8a9199}
  .${NS}-typing::after{content:'▋';animation:${NS}-b 1s steps(1) infinite;color:#4ec9b0}
  @keyframes ${NS}-b{50%{opacity:0}}
  `;
  function injectCSS(){if(document.getElementById(NS+'-css'))return;const s=document.createElement('style');s.id=NS+'-css';s.textContent=CSS;document.head.appendChild(s);}
  const esc=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

  function mount(el,opts){
    injectCSS();
    const root=typeof el==='string'?document.getElementById(el):el;
    if(!root)return;
    const scene=opts.scene; const history=[];
    root.innerHTML=`<div class="${NS}">
      <div class="${NS}-head"><span style="font-size:15px">✨</span><b>AI 辅助分析</b><span style="flex:1"></span><span style="font-size:11px;color:#8a9199;cursor:pointer" onclick="this.closest('.${NS}-wrap').style.display='none'">⟨ 收起</span></div>
      <div class="${NS}-ctx">上下文：<span data-ctx>自动采集</span></div>
      <div class="${NS}-body" data-body></div>
      <div class="${NS}-quick" data-quick></div>
      <div class="${NS}-input"><input placeholder="问任何相关问题…（Enter 发送）" data-in><button class="${NS}-send" data-send>发送</button></div>
      <div class="${NS}-privacy">🔒 内容脱敏后发往内网 LLM · AI 只建议不执行 · 交互全量审计</div>
    </div>`;
    const body=root.querySelector('[data-body]'),inp=root.querySelector('[data-in]'),quick=root.querySelector('[data-quick]'),ctxEl=root.querySelector('[data-ctx]');

    (opts.quickActions||[]).forEach(a=>{
      const b=document.createElement('span');b.className=NS+'-qb';b.textContent=a.label;
      b.onclick=()=>ask(a.question);quick.appendChild(b);
    });

    function renderCtx(){
      const h=opts.getHandle?opts.getHandle():{};
      const chips=[];
      if(h.asset)chips.push(h.asset);
      if(h.db)chips.push(h.db);
      if(h.selection)chips.push('选中 '+(h.selection.length>14?h.selection.slice(0,14)+'…':h.selection));
      if(h.fsid)chips.push('SQL 会话');
      ctxEl.innerHTML=chips.length?chips.map(c=>`<span class="${NS}-chip">${esc(c)}</span>`).join(''):'<span style="opacity:.6">无（可直接提问）</span>';
    }
    renderCtx();

    function bubble(cls,html){const d=document.createElement('div');d.className=NS+'-b '+cls;d.innerHTML=html;body.appendChild(d);body.scrollTop=body.scrollHeight;return d;}
    function fmt(t){
      // 简易 markdown：```code``` 与 **bold**
      let out=esc(t);
      out=out.replace(/```(\w*)\n?([\s\S]*?)```/g,(m,l,c)=>`<div class="${NS}-code"><span class="${NS}-copy" onclick="navigator.clipboard.writeText(this.parentNode.textContent.replace(/^⧉ Copy$/,''))">⧉ Copy</span>${c}</div>`);
      out=out.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>');
      return out;
    }
    let busy=false;
    async function ask(q){
      if(busy||!q)return;busy=true;renderCtx();
      bubble(NS+'-bu',esc(q));
      const ai=bubble(NS+'-ba','<span class="'+NS+'-typing">✨ 分析中…</span>');
      const handle=opts.getHandle?opts.getHandle():{};
      try{
        const r=await fetch('/api/v1/ai/chat',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+opts.token()},
          body:JSON.stringify({scene,question:q,handle,history:history.slice(-6)})});
        if(!r.ok){const e=await r.json().catch(()=>({}));ai.innerHTML='❌ '+(e.detail||('HTTP '+r.status));return}
        const reader=r.body.getReader(),dec=new TextDecoder();
        let ans='',think='',buf='';
        for(;;){
          const{done,value}=await reader.read();if(done)break;
          buf+=dec.decode(value,{stream:true});
          const lines=buf.split('\n\n');buf=lines.pop();
          for(const ln of lines){
            if(!ln.startsWith('data:'))continue;
            let d;try{d=JSON.parse(ln.slice(5))}catch(e){continue}
            if(d.error){ai.innerHTML='❌ '+esc(d.error);busy=false;history.push({role:'user',content:q});return}
            if(d.reasoning){think+=d.reasoning}
            if(d.delta){ans+=d.delta;ai.innerHTML=(think?`<div class="${NS}-think">${esc(think.slice(-400))}</div>`:'')+fmt(ans);body.scrollTop=body.scrollHeight}
          }
        }
        if(!ans)ai.innerHTML=(think?`<div class="${NS}-think">${esc(think.slice(-600))}</div>`:'')+'（模型未返回内容）';
        history.push({role:'user',content:q});if(ans)history.push({role:'assistant',content:ans});
      }catch(e){ai.innerHTML='❌ 网络错误：'+esc(e.message)}
      busy=false;
    }
    root.querySelector('[data-send]').onclick=()=>{ask(inp.value.trim());inp.value=''};
    inp.addEventListener('keydown',e=>{if(e.key==='Enter'){ask(inp.value.trim());inp.value=''}});
    if(opts.onReady)opts.onReady({ask});
    return {ask,setScene:s=>{opts.scene=s}};
  }
  window.NB_AI={mount};
})();
