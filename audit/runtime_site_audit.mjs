#!/usr/bin/env node
import { chromium, devices } from 'playwright';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';

const repo = path.resolve(process.argv[2] || '.');
const out = path.resolve(process.argv[3] || 'audit-results/runtime-site');
fs.mkdirSync(out, {recursive:true});
const sitesRoot = path.join(repo, 'sites');
const siteNames = fs.existsSync(sitesRoot) ? fs.readdirSync(sitesRoot).filter(n => fs.statSync(path.join(sitesRoot,n)).isDirectory()) : ['.'];

function walk(dir) {
  const out=[];
  for (const entry of fs.readdirSync(dir,{withFileTypes:true})) {
    if (['.git','node_modules','.cache','dist','build'].includes(entry.name)) continue;
    const p=path.join(dir,entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else if (/\.html?$/i.test(entry.name)) out.push(p);
  }
  return out;
}
function freePort() { return new Promise((resolve,reject)=>{ const s=net.createServer(); s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));}); s.on('error',reject); }); }
function wait(ms){return new Promise(r=>setTimeout(r,ms));}

const browser = await chromium.launch({headless:true});
const configs = [
  {name:'desktop', options:{viewport:{width:1440,height:1000}}},
  {name:'mobile', options:{...devices['iPhone 13']}}
];
const report={generatedAt:new Date().toISOString(),sites:{},failures:[]};
for (const siteName of siteNames) {
  const root = siteName==='.' ? repo : path.join(sitesRoot,siteName);
  const pages=walk(root).sort();
  if (!pages.length) continue;
  const port=await freePort();
  const server=spawn('python',['-m','http.server',String(port),'--bind','127.0.0.1'],{cwd:root,stdio:['ignore','pipe','pipe']});
  await wait(800);
  const site={root:path.relative(repo,root),pageCount:pages.length,devices:{}};
  report.sites[siteName]=site;
  for (const cfg of configs) {
    const context=await browser.newContext(cfg.options);
    site.devices[cfg.name]={pages:{}};
    for (const file of pages) {
      const rel=path.relative(root,file).split(path.sep).join('/');
      const url=`http://127.0.0.1:${port}/${encodeURI(rel)}?audit=${Date.now()}`;
      const page=await context.newPage();
      const requestFailures=[]; const consoleErrors=[]; const pageErrors=[];
      page.on('requestfailed',r=>requestFailures.push({url:r.url(),error:r.failure()?.errorText||''}));
      page.on('console',m=>{if(m.type()==='error')consoleErrors.push(m.text());});
      page.on('pageerror',e=>pageErrors.push(String(e)));
      let navigationError='';
      try {
        await page.goto(url,{waitUntil:'domcontentloaded',timeout:45000});
        const height=await page.evaluate(()=>document.documentElement.scrollHeight);
        for(let y=0;y<height;y+=750){await page.evaluate(v=>window.scrollTo(0,v),y);await page.waitForTimeout(60);}
        await page.evaluate(()=>window.scrollTo(0,document.documentElement.scrollHeight));
        await page.waitForTimeout(500);
      } catch(e){navigationError=String(e);}
      const state=await page.evaluate(()=>({
        title:document.title,
        htmlLang:document.documentElement.lang,
        images:[...document.images].map(i=>({src:i.currentSrc||i.src,complete:i.complete,naturalWidth:i.naturalWidth,naturalHeight:i.naturalHeight,display:getComputedStyle(i).display,visibility:getComputedStyle(i).visibility,opacity:getComputedStyle(i).opacity})),
        forms:[...document.forms].map(f=>({action:f.action,method:f.method,inputs:[...f.elements].map(e=>({name:e.name,type:e.type,required:e.required}))})),
        links:[...document.links].map(a=>a.href),
        scripts:[...document.scripts].map(s=>s.src).filter(Boolean)
      }));
      const brokenImages=state.images.filter(i=>!i.complete||!i.naturalWidth||!i.naturalHeight);
      const assetFailures=requestFailures.filter(x=>/\.(?:jpg|jpeg|png|webp|gif|svg|css|js|mjs|mp4|woff2?)(?:\?|$)/i.test(x.url));
      const record={url,navigationError,brokenImages,assetFailures,requestFailures,consoleErrors,pageErrors,state};
      site.devices[cfg.name].pages[rel]=record;
      if(navigationError||brokenImages.length||assetFailures.length||pageErrors.length) report.failures.push({site:siteName,device:cfg.name,page:rel,navigationError,brokenImages,assetFailures,pageErrors});
      await page.close();
    }
    await context.close();
  }
  server.kill('SIGTERM');
}
await browser.close();
report.status=report.failures.length?'FAIL':'PASS';
report.totalPages=Object.values(report.sites).reduce((n,s)=>n+s.pageCount,0);
report.totalRendered=Object.values(report.sites).reduce((n,s)=>n+Object.values(s.devices).reduce((m,d)=>m+Object.keys(d.pages).length,0),0);
fs.writeFileSync(path.join(out,'runtime-site-audit.json'),JSON.stringify(report,null,2)+'\n');
fs.writeFileSync(path.join(out,'runtime-site-failures.json'),JSON.stringify(report.failures,null,2)+'\n');
console.log(JSON.stringify({status:report.status,sites:Object.keys(report.sites),totalPages:report.totalPages,totalRendered:report.totalRendered,failureCount:report.failures.length},null,2));
process.exitCode=report.failures.length?1:0;
