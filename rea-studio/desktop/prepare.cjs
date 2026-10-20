const fs = require('node:fs'); const path = require('node:path');
const root = path.resolve(__dirname, '..');
function copy(src, dst) { fs.rmSync(dst, {recursive:true, force:true}); fs.cpSync(src,dst,{recursive:true}); }
copy(path.join(root,'index.html'),path.join(__dirname,'renderer','index.html'));
copy(path.join(root,'app.js'),path.join(__dirname,'renderer','app.js'));
copy(path.join(root,'styles.css'),path.join(__dirname,'renderer','styles.css'));
copy(path.join(root,'local-service'),path.join(__dirname,'local-service'));
console.log('Prepared renderer and local-service resources.');
