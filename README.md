# Security audit: justinmeiners/lc3-vm

Date: 2026-11-15 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 2 issue(s): 2 high.

## Findings

### 1. [HIGH] DOM XSS via innerHTML

**CWE-79** | `docs/google-code-prettify/run_prettify.js` line 30

Setting innerHTML with user data allows script injection in other users' browsers.

```
b.innerHTML="<pre>"+a+"</pre>";b=b.firstChild;e&&A(b,e,!0);E({h:d,j:e,c:b,i:1});return b.innerHTML},prettyPrint:e=e=function(a,d){function e(){for(var b=V.PR_SHOULD_USE_CONTINUATION?c.now()+250:Infinity;p<o.length&&c.now()<b;p++){for(var d=o[p],l=i,j=d;j=j.previousSibling;){var m=j.nodeType,s=(m===7||m===8)&&j.nodeValue;if(s?!/^\??prettify\b/.test(s):m!==3||/\S/.test(j.nodeValue))break;if(s){l={};s.replace(/\b(\w+)=([\w%+\-.:]+)/g,function(a,b,c){l[b]=c});break}}j=d.className;if((l!==i||f.test(j))&&
```

**Fix:** Use textContent. If HTML is needed, sanitize with DOMPurify.sanitize() first.
---

### 2. [HIGH] DOM XSS via innerHTML

**CWE-79** | `docs/google-code-prettify/prettify.js` line 26

Setting innerHTML with user data allows script injection in other users' browsers.

```
document.createElement("div");b.innerHTML="<pre>"+a+"</pre>";b=b.firstChild;g&&J(b,g,!0);K({h:d,j:g,c:b,i:1});return b.innerHTML},prettyPrint:E.prettyPrint=function(a,d){function g(){for(var b=E.PR_SHOULD_USE_CONTINUATION?c.now()+250:Infinity;i<q.length&&c.now()<b;i++){for(var d=q[i],j=h,k=d;k=k.previousSibling;){var m=k.nodeType,o=(m===7||m===8)&&k.nodeValue;if(o?!/^\??prettify\b/.test(o):m!==3||/\S/.test(k.nodeValue))break;if(o){j={};o.replace(/\b(\w+)=([\w%+\-.:]+)/g,function(a,b,c){j[b]=c});break}}k=
```

**Fix:** Use textContent. If HTML is needed, sanitize with DOMPurify.sanitize() first.
---
