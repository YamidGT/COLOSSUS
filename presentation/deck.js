'use strict';
const slides=[...document.querySelectorAll('.slide')];
const counter=document.querySelector('#counter');
const previous=document.querySelector('#previous');
const next=document.querySelector('#next');
const dots=document.querySelector('#dots');
const notes=document.querySelector('#notes');
const notesPanel=document.querySelector('#notes-panel');
let current=0;
slides.forEach((slide,index)=>{const button=document.createElement('button');button.type='button';button.setAttribute('aria-label',`Slide ${index+1}: ${slide.dataset.title}`);button.addEventListener('click',()=>show(index));dots.append(button)});
function show(index,updateHash=true){current=Math.max(0,Math.min(slides.length-1,index));slides.forEach((slide,i)=>{slide.hidden=i!==current;slide.classList.toggle('active',i===current)});[...dots.children].forEach((dot,i)=>dot.setAttribute('aria-current',String(i===current)));counter.textContent=`${String(current+1).padStart(2,'0')} / ${String(slides.length).padStart(2,'0')}`;document.querySelector('#slide-title').textContent=slides[current].dataset.title;document.querySelector('#notes-content').textContent=slides[current].querySelector('.notes').textContent;previous.disabled=current===0;next.disabled=current===slides.length-1;document.title=`${current+1}. ${slides[current].dataset.title} — COLOSSUS`;if(updateHash)history.replaceState(null,'',`#${current+1}`);window.scrollTo({top:0,behavior:'instant'})}
function fromHash(){const n=Number(location.hash.slice(1));show(Number.isInteger(n)&&n>=1&&n<=slides.length?n-1:0,false)}
previous.addEventListener('click',()=>show(current-1));next.addEventListener('click',()=>show(current+1));
notes.addEventListener('click',()=>{notesPanel.hidden=!notesPanel.hidden;notes.setAttribute('aria-pressed',String(!notesPanel.hidden))});
document.querySelector('#fullscreen').addEventListener('click',async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await document.documentElement.requestFullscreen()}catch{document.querySelector('#fullscreen').textContent='Use browser full screen'}});
document.addEventListener('fullscreenchange',()=>{document.querySelector('#fullscreen').textContent=document.fullscreenElement?'Exit full screen ⛶':'Full screen ⛶'});
window.addEventListener('hashchange',fromHash);
document.addEventListener('keydown',event=>{if(event.target instanceof HTMLElement&&(['INPUT','TEXTAREA','SELECT'].includes(event.target.tagName)||event.target.isContentEditable))return;if(['ArrowRight','PageDown'].includes(event.key)){event.preventDefault();show(current+1)}else if(['ArrowLeft','PageUp'].includes(event.key)){event.preventDefault();show(current-1)}else if(event.key==='Home'){event.preventDefault();show(0)}else if(event.key==='End'){event.preventDefault();show(slides.length-1)}else if(event.key==='Escape'&&!notesPanel.hidden){notesPanel.hidden=true;notes.setAttribute('aria-pressed','false')}});
fromHash();
