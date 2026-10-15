const { chromium } = require('C:/Users/double/.workbuddy/binaries/node/workspace/node_modules/playwright-core');
const R = {pass:0,fail:0,results:[]};
function check(name,cond,detail=''){
  R[cond?'pass':'fail']++;R.results.push({name,ok:!!cond,detail:String(detail).slice(0,90)});
  console.log(cond?'✅':'❌',name,detail&&!cond?'→ '+detail:'');
}
(async()=>{
  const b=await chromium.launch({headless:true,executablePath:'C:/Users/double/AppData/Local/ms-playwright/chromium-1248/chrome-win64/chrome.exe',args:['--ignore-certificate-errors']});
  const ctx=await b.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:900}});
  const lr=await fetch('https://192.168.110.114/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'hiti.123'})});
  const tok=(await lr.json()).data.access_token;

  // ===== 登录页 =====
  const lp=await ctx.newPage();
  await lp.goto('https://192.168.110.114/',{waitUntil:'domcontentloaded'});
  const hasLogin=await lp.$('input[type=password],#login,.login-box,.login-card').catch(()=>null);
  const anyInput=await lp.$$('input');
  check('登录页渲染',anyInput.length>0);
  await lp.close();

  // ===== 主界面（SPA 各页面）=====
  const pg=await ctx.newPage();
  const errs=[];
  pg.on('pageerror',e=>errs.push(String(e).slice(0,100)));
  await pg.goto('https://192.168.110.114/',{waitUntil:'domcontentloaded'});
  await pg.evaluate(t=>{sessionStorage.setItem('nb_token',t);sessionStorage.setItem('nb_user',JSON.stringify({id:1,username:'admin',role:'admin',display_name:'admin'}));},tok);
  await pg.reload();await pg.waitForTimeout(1500);
  const pages=['dashboard','myassets','assets','policies','users','sessions','commands','transfers','acctscan','settings'];
  for(const p of pages){
    errs.length=0;
    await pg.evaluate(x=>go(x),p);await pg.waitForTimeout(1400);
    const h2=await pg.textContent('h2').catch(()=>'');
    const nav=await pg.$$('.nav-item');
    const hasCard=await pg.$$('.card, .empty');
    check(`页面[${p}] "${h2.trim().slice(0,14)}"`,h2&&nav.length>5&&hasCard.length>0,`h2=${h2.trim().slice(0,20)}`);
    if(p==='myassets'){
      const rows=await pg.$$('#my-assets-table tbody tr').then(e=>e.length).catch(()=>0);
      check('我的资产含 8 台(节点继承)',rows>=8,'行数='+rows);
      await pg.screenshot({path:'demo/rt-myassets.png'});
    }
    if(p==='transfers'){await pg.screenshot({path:'demo/rt-transfers.png'});}
    if(p==='acctscan'){await pg.screenshot({path:'demo/rt-acctscan.png'});}
    if(p==='settings'){
      const sl=await pg.$('#syslog-card');
      check('设置页 Syslog 卡片',!!sl);
      await pg.screenshot({path:'demo/rt-settings.png'});
    }
    if(errs.length)check(`页面[${p}] JS错误`,false,errs[0]);
  }
  // 策略表单（弹窗）
  await pg.evaluate(()=>go('policies'));await pg.waitForTimeout(1200);
  await pg.evaluate(()=>{const b=document.querySelector('.page-head .btn-primary');if(b)b.click()});
  await pg.waitForTimeout(1500);
  const sftpSw=await pg.$('#p-sftp');
  check('策略表单 SFTP 开关',!!sftpSw);
  const clipSw=await pg.$('#p-clip');
  check('策略表单 剪贴板开关',!!clipSw);
  await pg.screenshot({path:'demo/rt-policy-form.png'});
  await pg.evaluate(()=>closeModal&&closeModal()).catch(()=>{});
  // 资产编辑弹窗（托管+取消托管按钮）
  await pg.evaluate(()=>go('assets'));await pg.waitForTimeout(1500);
  const trs=await pg.$$('tbody tr');
  let tr=null;for(const t of trs){if((await t.textContent()).includes('self-bastion')){tr=t;break}}
  if(tr){for(const btn of await tr.$$('button')){if((await btn.textContent()).includes('编辑')){await btn.click();break}}
    await pg.waitForTimeout(1200);
    const un=await pg.$$eval('.modal-body button',els=>els.some(e=>e.textContent.includes('取消托管')));
    check('资产编辑含取消托管按钮',un);
    await pg.evaluate(()=>closeModal()).catch(()=>{});
  }

  // ===== 终端页（托管账号真实 SSH）=====
  const tp=await ctx.newPage();const terr=[];
  tp.on('pageerror',e=>terr.push(String(e).slice(0,100)));
  await tp.goto(`https://192.168.110.114/terminal.html?token=${tok}&asset=1&account=1&user=admin`,{waitUntil:'domcontentloaded'});
  await tp.waitForTimeout(4000);
  const info=await tp.textContent('#info').catch(()=>'');
  check('终端页 SSH 会话',info.includes('会话'),'info='+info.trim().slice(0,40));
  const fileBtn=await tp.$('.btn-f');
  check('终端头部 📁文件 按钮',!!fileBtn);
  await tp.screenshot({path:'demo/rt-terminal.png'});
  await tp.close();

  // ===== 文件管理页（含高危目录标记）=====
  const fp=await ctx.newPage();const ferr=[];
  fp.on('pageerror',e=>ferr.push(String(e).slice(0,100)));
  await fp.goto(`https://192.168.110.114/fileman.html?token=${tok}&asset=1&account=1`,{waitUntil:'domcontentloaded'});
  await fp.waitForTimeout(4500);
  const rows=await fp.$$eval('#rows .frow',e=>e.length).catch(()=>0);
  const stat=await fp.textContent('#stat').catch(()=>'');
  check('文件管理连接+列目录',rows>0,stat.trim().slice(0,30));
  const disc=await fp.$('#btn-disc');
  check('文件管理断开按钮',!!disc);
  await fp.screenshot({path:'demo/rt-fileman.png'});
  await fp.close();

  // ===== RDP 页（win-demo 会失败但页面应渲染错误提示而非白屏）=====
  const rp=await ctx.newPage();
  await rp.goto(`https://192.168.110.114/rdp.html?token=x&user=admin`,{waitUntil:'domcontentloaded'});
  await rp.waitForTimeout(2500);
  const rdpBar=await rp.textContent('.bar').catch(()=>'');
  check('RDP 页面顶栏渲染',rdpBar.includes('断开'));
  await rp.close();

  // ===== 录像播放器页（历史会话）=====
  const pl=await ctx.newPage();
  await pl.goto(`https://192.168.110.114/player.html?token=${tok}&sid=S-20261014-c612c92b&user=admin`,{waitUntil:'domcontentloaded'});
  await pl.waitForTimeout(2000);
  const plRender=await pl.$$eval('body *',e=>e.length).catch(()=>0);
  check('SSH 录像播放器渲染',plRender>10);
  await pl.close();

  console.log(`\n===== 前端总计: ${R.pass} 通过 / ${R.fail} 失败 =====`);
  require('fs').writeFileSync('frontend_test_results.json',JSON.stringify(R,null,1));
  await b.close();
})().catch(e=>{console.error('FATAL:',e.message);process.exit(1)});
