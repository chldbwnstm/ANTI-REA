//! Trusted Cargo RUSTC_WRAPPER source (std only); compile/check before use.
//! Caller must own a bounded Cargo Job; child.kill alone is not tree cleanup.
use std::{collections::BTreeMap, env, fs::{self, File, OpenOptions}, io::{Read, Write},
          path::{Path, PathBuf}, process::{Command, Stdio}, thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
#[cfg(windows)] use std::os::windows::fs::MetadataExt;
#[cfg(windows)] use std::os::windows::io::AsRawHandle;

type R<T> = Result<T, String>;
const TARGET:&str="x86_64-pc-windows-msvc";

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct HandleInfo { attributes:u32, creation:[u32;2], access:[u32;2], write:[u32;2], volume:u32,
                    size_high:u32, size_low:u32, links:u32, index_high:u32, index_low:u32 }
#[cfg(windows)]
#[link(name="kernel32")]
unsafe extern "system" {fn GetFileInformationByHandle(handle:*mut std::ffi::c_void,info:*mut HandleInfo)->i32;}
fn file_identity(path:&Path)->R<(String,u64)> {
    #[cfg(windows)] {
        let file=File::open(path).map_err(|e|e.to_string())?;
        let mut info=HandleInfo::default();
        // Layout matches installed Windows SDK fileapi.h BY_HANDLE_FILE_INFORMATION.
        if unsafe {GetFileInformationByHandle(file.as_raw_handle(),&mut info)}==0{return Err(std::io::Error::last_os_error().to_string());}
        if info.attributes&(0x400|0x10)!=0{return Err("file handle is reparse/directory".into());}
        return Ok((format!("{:08x}:{:08x}{:08x}",info.volume,info.index_high,info.index_low),info.links as u64));
    }
    #[cfg(unix)] {use std::os::unix::fs::MetadataExt;let md=fs::metadata(path).map_err(|e|e.to_string())?;return Ok((format!("{:x}:{:x}",md.dev(),md.ino()),md.nlink()));}
    #[cfg(not(any(windows,unix)))] {let _=path;Err("unsupported file identity platform".into())}
}

// SHA-256, not a non-cryptographic substitute. Every newly built recorder needs
// its tests and compiled --self-test cross-checked with Python hashlib before use.
struct Sha { h: [u32;8], block: [u8;64], used: usize, bytes: u64 }
impl Sha {
    fn new() -> Self { Self {h:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],block:[0;64],used:0,bytes:0} }
    fn compress(&mut self) {
        const K:[u32;64]=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
        let mut w=[0u32;64];
        for (i, word) in w.iter_mut().take(16).enumerate() { *word=u32::from_be_bytes(self.block[i*4..i*4+4].try_into().unwrap()); }
        for i in 16..64 { let a=w[i-15]; let b=w[i-2]; w[i]=w[i-16].wrapping_add(a.rotate_right(7)^a.rotate_right(18)^(a>>3)).wrapping_add(w[i-7]).wrapping_add(b.rotate_right(17)^b.rotate_right(19)^(b>>10)); }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut h]=self.h;
        for i in 0..64 { let t=h.wrapping_add(e.rotate_right(6)^e.rotate_right(11)^e.rotate_right(25)).wrapping_add((e&f)^(!e&g)).wrapping_add(K[i]).wrapping_add(w[i]); let u=(a.rotate_right(2)^a.rotate_right(13)^a.rotate_right(22)).wrapping_add((a&b)^(a&c)^(b&c)); h=g;g=f;f=e;e=d.wrapping_add(t);d=c;c=b;b=a;a=t.wrapping_add(u); }
        for (slot,value) in self.h.iter_mut().zip([a,b,c,d,e,f,g,h]) { *slot=slot.wrapping_add(value); }
    }
    fn update(&mut self, bytes:&[u8]) { self.bytes=self.bytes.checked_add(bytes.len() as u64).expect("SHA input length"); for &byte in bytes { self.block[self.used]=byte;self.used+=1;if self.used==64 {self.compress();self.used=0;} } }
    fn finish(mut self)->String { let bits=self.bytes.checked_mul(8).expect("SHA length"); self.block[self.used]=0x80;self.used+=1;if self.used>56 {self.block[self.used..].fill(0);self.compress();self.used=0;}self.block[self.used..56].fill(0);self.block[56..].copy_from_slice(&bits.to_be_bytes());self.compress();self.h.iter().map(|x|format!("{x:08x}")).collect() }
}
fn sha(bytes:&[u8])->String { let mut hash=Sha::new();hash.update(bytes);hash.finish() }
fn file_sha_inner(path:&Path,owned_links:bool)->R<String> { check_path_inner(path,owned_links)?;let mut file=File::open(path).map_err(|e|e.to_string())?;let mut hash=Sha::new();let mut block=[0u8;65536];loop {let n=file.read(&mut block).map_err(|e|e.to_string())?;if n==0 {break;}hash.update(&block[..n]);}Ok(hash.finish()) }
fn file_sha(path:&Path)->R<String>{file_sha_inner(path,false)}
// The fixed installed linker may have OS-maintained aliases. All other tools,
// owned sources and policy/record files retain the no-hardlink requirement.
fn tool_sha(path:&Path,kind:&str)->R<String>{file_sha_inner(path,kind=="linker")}
fn quote(value:&str)->String { let mut out=String::from("\"");for ch in value.chars(){match ch {'"'=>out.push_str("\\\""),'\\'=>out.push_str("\\\\"),'\n'=>out.push_str("\\n"),'\r'=>out.push_str("\\r"),'\t'=>out.push_str("\\t"),'\u{8}'=>out.push_str("\\b"),'\u{c}'=>out.push_str("\\f"),ch if ch<' '=>out.push_str(&format!("\\u{:04x}",ch as u32)),ch=>out.push(ch)}}out.push('"');out }
fn array(values:&[String])->String { format!("[{}]",values.iter().map(|x|quote(x)).collect::<Vec<_>>().join(",")) }
fn object(values:&BTreeMap<String,String>,raw:bool)->String { format!("{{{}}}",values.iter().map(|(k,v)|format!("{}:{}",quote(k),if raw {v.clone()} else {quote(v)})).collect::<Vec<_>>().join(",")) }
fn write_new(path:&Path,bytes:&[u8])->R<()> { check_path(path.parent().ok_or("missing parent")?)?;let mut file=OpenOptions::new().write(true).create_new(true).open(path).map_err(|e|e.to_string())?;file.write_all(bytes).and_then(|_|file.sync_all()).map_err(|e|e.to_string()) }
fn text(path:&Path)->R<String> { path.to_str().map(str::to_string).ok_or("non-Unicode paths cannot be recorded losslessly".into()) }
fn check_path_inner(path:&Path,owned_links:bool)->R<()> {
    if !path.is_absolute() || path.components().any(|x|matches!(x,std::path::Component::ParentDir)) {return Err("absolute normalized path required".into());}
    let spelling=path.to_str().ok_or("non-Unicode path cannot be checked losslessly")?;
    if spelling.starts_with("\\\\")||spelling.starts_with("//")||path.components().any(|component|matches!(component,std::path::Component::Normal(value) if value.to_str().is_none_or(|text|text.contains(':')))){return Err("raw device/UNC/alternate-stream path refused".into());}
    for part in path.ancestors() { match fs::symlink_metadata(part) {Ok(md)=>{
        if md.file_type().is_symlink() {return Err("symlink input/output refused".into());}
        #[cfg(windows)] if md.file_attributes()&0x400 !=0 {return Err("reparse input/output refused".into());}
        if md.is_file()&&!owned_links&&file_identity(part)?.1!=1{return Err("hardlinked input/tool/policy refused".into());}
    },Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(e.to_string())}}
    Ok(())
}
fn check_path(path:&Path)->R<()>{check_path_inner(path,false)}
fn canonical_path(path:&Path)->R<PathBuf> {check_path(path)?;path.canonicalize().map_err(|e|e.to_string())}
fn target_tree(root:&Path)->R<String> {
    fn scan(root:&Path)->R<String>{
        check_path(root)?;if !root.is_dir(){return Err("target root is not a directory".into());}
        let mut pending=vec![root.to_path_buf()];let mut directories=Vec::new();let mut files=Vec::new();
        while let Some(current)=pending.pop(){check_path(&current)?;directories.push(text(&current)?);if directories.len()>10000{return Err("target directory-count limit".into());}
            for entry in fs::read_dir(&current).map_err(|e|e.to_string())? {let path=entry.map_err(|e|e.to_string())?.path();check_path_inner(&path,true)?;let md=fs::symlink_metadata(&path).map_err(|e|e.to_string())?;
                if md.is_dir(){pending.push(path);}else if md.is_file(){let (identity,links)=file_identity(&path)?;files.push((text(&path)?,identity,links));if files.len()>10000{return Err("target file-count limit".into());}}
                else{return Err("unsupported target leaf type".into());}
            }
        }
        let mut aliases=BTreeMap::new();for (_,id,_) in &files{*aliases.entry(id.clone()).or_insert(0u64)+=1;}
        if files.iter().any(|(_,id,links)|aliases.get(id)!=Some(links)){return Err("target hardlinks have unaccounted/external aliases".into());}
        directories.sort();files.sort();let encoded=files.iter().map(|(path,id,links)|format!("{{\"identity\":{},\"links\":{},\"path\":{}}}",quote(id),links,quote(path))).collect::<Vec<_>>();
        Ok(format!("{{\"directories\":{},\"files\":[{}],\"root\":{}}}",array(&directories),encoded.join(","),quote(&text(root)?)))
    }
    let first=scan(root)?;let second=scan(root)?;if first!=second{return Err("target alias tree changed while inspected".into());}Ok(first)
}

struct Policy { one:BTreeMap<String,String>, roots:Vec<PathBuf>, sources:Vec<PathBuf>, sha:String }
impl Policy {
    fn load(path:&Path)->R<Self> {
        check_path(path)?;let bytes=fs::read(path).map_err(|e|e.to_string())?;
        if bytes.len()>1024*1024{return Err("policy too large".into());}
        let body=std::str::from_utf8(&bytes).map_err(|e|e.to_string())?;
        let mut one=BTreeMap::new();let mut roots=Vec::new();let mut sources=Vec::new();
        for line in body.lines(){let (key,value)=line.split_once('=').ok_or("malformed policy line")?;
            if value.is_empty() || value.contains('\0') {return Err("empty/NUL policy value".into());}
            match key {"input_root"=>roots.push(PathBuf::from(value)),"source"=>sources.push(PathBuf::from(value)),
                "schema"|"mode"|"backend"|"backend_sha256"|"backend_host"|"wrapper"|"wrapper_sha256"|"linker"|"linker_sha256"|"workspace"|"record_root"|"target_root"|"sysroot"|"stop"=>{if one.insert(key.to_string(),value.to_string()).is_some(){return Err("duplicate policy key".into());}},_=>return Err("unknown policy field".into())}
        }
        if one.len()!=14 || one.get("schema").map(String::as_str)!=Some("1") || one.get("backend_host").map(String::as_str)!=Some(TARGET) || !matches!(one.get("mode").map(String::as_str),Some("original"|"derivative")) || roots.is_empty() || sources.is_empty(){return Err("incomplete policy/fixed backend host contract".into());}
        for name in ["backend_sha256","wrapper_sha256","linker_sha256"] {if one[name].len()!=64 || !one[name].bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err("invalid SHA256 pin".into());}}
        let workspace=canonical_path(Path::new(&one["workspace"]))?;
        for root in &roots {let p=canonical_path(root)?;if p==workspace || !p.starts_with(&workspace){return Err("unowned/broad source root".into());}}
        for source in &sources {let p=canonical_path(source)?;if !roots.iter().any(|r|canonical_path(r).is_ok_and(|r|p.starts_with(r))){return Err("source outside pinned roots".into());}}
        for name in ["record_root","target_root"] {let p=canonical_path(Path::new(&one[name]))?;if !p.starts_with(workspace.join(".runs")){return Err("output root outside .runs".into());}if roots.iter().any(|r|canonical_path(r).is_ok_and(|r|p.starts_with(&r)||r.starts_with(&p))){return Err("output overlaps source".into());}}
        if Path::new(&one["stop"]) != Path::new(&one["workspace"]).join(".runs/defense-loop/STOP") {return Err("unexpected STOP path".into());}
        Ok(Self{one,roots,sources,sha:sha(&bytes)})
    }
    fn get(&self,key:&str)->&str {&self.one[key]}
}

#[derive(Clone)] struct Row {key:String,value:Option<String>,tokens:Vec<String>}
fn value_option(key:&str)->bool {matches!(key,"--crate-name"|"--crate-type"|"--edition"|"--emit"|"--out-dir"|"--extern"|"--cfg"|"--check-cfg"|"--target"|"--error-format"|"--json"|"--cap-lints"|"--color"|"--diagnostic-width"|"--remap-path-prefix"|"--sysroot"|"--print"|"-C"|"-L"|"-l"|"-A"|"-W"|"-D"|"-F")}
fn codegen_option(key:&str)->bool {matches!(key,"opt-level"|"debug-assertions"|"overflow-checks"|"debuginfo"|"split-debuginfo"|"incremental"|"metadata"|"extra-filename"|"codegen-units"|"panic"|"strip"|"lto"|"embed-bitcode"|"no-prepopulate-passes"|"target-cpu"|"target-feature"|"relocation-model"|"linker")}
fn parse(args:&[String])->R<(Vec<Row>,String)> {
    let mut rows=Vec::new();let mut i=0;
    while i<args.len(){let arg=&args[i];if arg.starts_with('@'){return Err("response files not pinned".into());}
        if matches!(arg.as_str(),"-vV"|"-V"|"--version"|"-g"|"-O"|"--test"){rows.push(Row{key:arg.clone(),value:None,tokens:vec![arg.clone()]});i+=1;continue;}
        if let Some((key,value))=arg.split_once('='){if value_option(key){if value.is_empty(){return Err("empty option".into());}rows.push(Row{key:key.into(),value:Some(value.into()),tokens:vec![arg.clone()]});i+=1;continue;}}
        if value_option(arg){if i+1==args.len()||args[i+1].is_empty(){return Err("missing option value".into());}rows.push(Row{key:arg.clone(),value:Some(args[i+1].clone()),tokens:args[i..i+2].to_vec()});i+=2;continue;}
        if arg.len()>2 && ["-C","-L","-l","-A","-W","-D","-F"].iter().any(|p|arg.starts_with(p)){rows.push(Row{key:arg[..2].into(),value:Some(arg[2..].into()),tokens:vec![arg.clone()]});i+=1;continue;}
        if arg.starts_with('-')&&arg!="-"{return Err(format!("unsupported rustc option: {arg}"));}
        rows.push(Row{key:"source".into(),value:Some(arg.clone()),tokens:vec![arg.clone()]});i+=1;
    }
    for row in &rows {if row.key=="-C"&&!codegen_option(row.value.as_deref().unwrap_or("").split('=').next().unwrap_or("")){return Err("unsupported rustc codegen selector".into());}if row.key=="-l"{return Err("explicit native library argument requires pinned link contract".into());}}
    let values=|key:&str|rows.iter().filter(|r|r.key==key).filter_map(|r|r.value.clone()).collect::<Vec<_>>();
    let source=values("source");let prints=values("--print");
    let targets=values("--target");if targets.len()>1||targets.iter().any(|target|target!=TARGET){return Err("target must be exactly one fixed Windows x64 triple, not JSON".into());}
    let version=rows.iter().any(|r|matches!(r.key.as_str(),"-vV"|"-V"|"--version"));
    let kind=if version {if args.len()!=1{return Err("ambiguous version probe".into());}"probe"}
    else if !prints.is_empty(){if prints.iter().any(|x|!matches!(x.as_str(),"cfg"|"sysroot"|"target-libdir"|"file-names"|"split-debuginfo"|"crate-name"|"target-list"))||!values("--emit").is_empty()||!values("--out-dir").is_empty()||!(source.is_empty()||source==vec!["-".to_string()]){return Err("ambiguous print probe".into());}"probe"}
    else {for key in ["--crate-name","--emit","--out-dir","--target"]{if values(key).len()!=1{return Err(format!("unit needs exactly one {key}"));}}
        let kinds=values("--crate-type").iter().flat_map(|value|value.split(',').map(str::to_string)).collect::<Vec<_>>();let mut unique_kinds=kinds.clone();unique_kinds.sort();unique_kinds.dedup();
        if source.len()!=1||source[0]=="-"||rows.iter().any(|r|r.key=="--test")||kinds.is_empty()||unique_kinds.len()!=kinds.len()||kinds.iter().any(|k|!matches!(k.as_str(),"lib"|"rlib"|"cdylib"|"staticlib")){return Err("unsupported/duplicate compile target kind".into());}
        let emit=values("--emit")[0].split(',').map(str::to_string).collect::<Vec<_>>();let mut unique=emit.clone();unique.sort();unique.dedup();
        if unique.len()!=emit.len()||emit.iter().any(|x|!matches!(x.as_str(),"dep-info"|"metadata"|"link"|"llvm-ir"))||!emit.contains(&"dep-info".into())||!emit.contains(&"link".into()){return Err("unsupported emit destination/mode in either arm".into());}
        let name=values("--crate-name")[0].clone();if name.is_empty()||!name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_')||name.as_bytes()[0].is_ascii_digit(){return Err("unsupported crate-name/output spelling".into());}
        for value in values("-C"){if let Some(tail)=value.strip_prefix("extra-filename="){if !tail.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)){return Err("unsupported extra-filename/output spelling".into());}}}
        "crate"};
    Ok((rows,kind.into()))
}
fn change(option:&str,before:&[String],after:&[String])->String {format!("{{\"after\":{},\"before\":{},\"option\":{}}}",array(after),array(before),quote(option))}
fn derive(args:&[String],mode:&str)->R<(Vec<Row>,String,Vec<String>,Vec<String>)> {
    let (rows,kind)=parse(args)?;if mode=="original"||kind=="probe"{return Ok((rows,kind,args.to_vec(),vec![]));}
    let mut out=Vec::new();let mut changes=Vec::new();
    for row in &rows {let value=row.value.as_deref().unwrap_or("");
        if row.key=="--emit" {let mut emit=value.split(',').map(str::to_string).collect::<Vec<_>>();let mut unique=emit.clone();unique.sort();unique.dedup();
            if unique.len()!=emit.len()||emit.iter().any(|v|!matches!(v.as_str(),"dep-info"|"metadata"|"link"|"llvm-ir"))||!emit.contains(&"dep-info".into())||!emit.contains(&"link".into()){return Err("unsupported emit output recipe".into());}
            if !emit.contains(&"llvm-ir".into()){emit.push("llvm-ir".into());}let after=vec![format!("--emit={}",emit.join(","))];changes.push(change("--emit",&row.tokens,&after));out.extend(after);
        }else if row.key=="-C"&&matches!(value.split('=').next().unwrap_or(""),"no-prepopulate-passes"|"embed-bitcode"|"codegen-units") {changes.push(change(&format!("-C {}",value.split('=').next().unwrap()),&row.tokens,&[]));}
        else {out.extend(row.tokens.clone());}
    }
    for (key,arg) in [("no-prepopulate-passes","-Cno-prepopulate-passes"),("embed-bitcode","-Cembed-bitcode=no"),("codegen-units","-Ccodegen-units=1")] {let after=vec![arg.to_string()];changes.push(change(&format!("-C {key}"),&[],&after));out.extend(after);}
    Ok((rows,kind,out,changes))
}

fn validate_linker(rows:&[Row],kind:&str,expected:&str)->R<()> {
    let values=rows.iter().filter(|row|row.key=="-C").filter_map(|row|row.value.as_deref())
        .filter(|value|value.split('=').next()==Some("linker"))
        .map(|value|value.split_once('=').map(|(_,path)|path).unwrap_or("")).collect::<Vec<_>>();
    if (kind=="crate"&&values!=vec![expected])||(kind=="probe"&&!values.is_empty()&&values!=vec![expected]) {
        return Err("actual rustc linker differs from the single pinned linker policy".into());
    }
    Ok(())
}

fn forward_environment<'a>(command:&'a mut Command,environment:&[(String,String)])->&'a mut Command {
    command.env_clear().envs(environment.iter().map(|(key,value)|(key,value)))
}

fn diagnostic_environment(environment:&BTreeMap<String,String>)->BTreeMap<String,String> {
    // Private recording only: never extend this allowlist to arbitrary env.
    ["PATH","CARGO_MAKEFLAGS"].into_iter().filter_map(|key|
        environment.get(key).map(|value|(key.to_string(),value.clone()))).collect()
}

fn run()->R<i32> {
    let all=env::args_os().skip(1).map(|x|x.into_string().map_err(|_|"non-Unicode argv cannot be recorded losslessly".to_string())).collect::<R<Vec<_>>>()?;
    if all==vec!["--self-test"] {let mut samples=["","abc","a\u{0000}b","한글/Ω","abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"].into_iter().map(str::to_string).collect::<Vec<_>>();let env_sample=[("Path","C:\\tools\\한글"),("private_sample","not-a-secret"),("ZZ_CONTROL","line\nNUL\0quote\"slash\\")].into_iter().map(|(key,value)|(key.to_uppercase(),value.to_string())).collect::<BTreeMap<_,_>>();samples.push(object(&env_sample,false));let values=samples.iter().map(|s|format!("{{\"input\":{},\"sha256\":{}}}",quote(s),quote(&sha(s.as_bytes())))).collect::<Vec<_>>();println!("[{}]",values.join(","));return Ok(0);}
    let policy_path=PathBuf::from(env::var("ANTIREA_RUST_UNIT_POLICY").map_err(|_|"missing trusted policy")?);
    let p=Policy::load(&policy_path)?;
    if Path::new(p.get("stop")).exists(){return Err("STOP set before compiler launch".into());}
    if all.is_empty()||canonical_path(Path::new(&all[0]))?!=canonical_path(Path::new(p.get("backend")))?{return Err("Cargo backend differs from policy".into());}
    if canonical_path(&env::current_exe().map_err(|e|e.to_string())?)?!=canonical_path(Path::new(p.get("wrapper")))?{return Err("wrapper identity differs from policy".into());}
    for kind in ["backend","wrapper","linker"] {if tool_sha(Path::new(p.get(kind)),kind)?!=p.get(&format!("{kind}_sha256")){return Err("actual tool hash differs from policy".into());}}
    let cwd=env::current_dir().map_err(|e|e.to_string())?;check_path(&cwd)?;
    let (rows,kind,forwarded,changes)=derive(&all[1..],p.get("mode"))?;
    validate_linker(&rows,&kind,p.get("linker"))?;
    let target_before=target_tree(Path::new(p.get("target_root")))?;
    let mut inputs=BTreeMap::new();
    if kind=="crate" {let source=PathBuf::from(rows.iter().find(|r|r.key=="source").unwrap().value.as_ref().unwrap());let source=if source.is_absolute(){source}else{cwd.join(source)};
        let canonical_source=canonical_path(&source)?;
        if !p.sources.iter().any(|allowed|canonical_path(allowed).is_ok_and(|x|x==canonical_source)){return Err("source outside metadata closure".into());}
        inputs.insert(text(&source)?,file_sha(&source)?);
        let out=PathBuf::from(rows.iter().find(|r|r.key=="--out-dir").unwrap().value.as_ref().unwrap());
        if !canonical_path(&out)?.starts_with(canonical_path(Path::new(p.get("target_root")))?){return Err("unit output outside its own target root".into());}
        for row in &rows {let value=row.value.as_deref().unwrap_or("");
            if row.key=="--sysroot"&&canonical_path(Path::new(value))?!=canonical_path(Path::new(p.get("sysroot")))?{return Err("explicit sysroot differs from pinned inputs".into());}
            if row.key=="-C" {if let Some(tail)=value.strip_prefix("incremental="){let path=Path::new(tail);check_path(path)?;if !path.starts_with(Path::new(p.get("target_root"))){return Err("incremental output outside own arm".into());}}}
            if row.key=="-L" {let (label,path)=value.split_once('=').ok_or("implicit library search unsupported")?;if label!="dependency"||!canonical_path(Path::new(path))?.starts_with(canonical_path(Path::new(p.get("target_root")))?){return Err("library search outside own dependency outputs".into());}}
        }
        for row in rows.iter().filter(|r|r.key=="--extern") {let (_,value)=row.value.as_ref().unwrap().split_once('=').ok_or("implicit extern search unsupported")?;let path=PathBuf::from(value);
            check_path_inner(&path,true)?;
            if !path.canonicalize().map_err(|e|e.to_string())?.starts_with(canonical_path(Path::new(p.get("target_root")))?)||!matches!(path.extension().and_then(|x|x.to_str()),Some("rlib"|"rmeta")){return Err("extern must be an owned local Cargo artifact".into());}
            inputs.insert(text(&path)?,file_sha_inner(&path,true)?);
        }
    }
    // Preserve names as well as values in the forwarded environment. Uppercase
    // only a separate recording map for deterministic Windows-key comparison.
    let mut environment=BTreeMap::new();let mut forwarded_environment=Vec::new();
    for (key,value) in env::vars_os(){let key=key.into_string().map_err(|_|"non-Unicode environment name")?;let value=value.into_string().map_err(|_|"non-Unicode environment value")?;if environment.insert(key.to_uppercase(),value.clone()).is_some(){return Err("case-ambiguous environment".into());}forwarded_environment.push((key,value));}
    let env_sha=sha(object(&environment,false).as_bytes());
    let env_hashes=environment.iter().map(|(k,v)|(k.clone(),sha(v.as_bytes()))).collect::<BTreeMap<_,_>>();
    let identity=["CARGO_MANIFEST_DIR","CARGO_MANIFEST_PATH","CARGO_PKG_NAME","CARGO_PKG_VERSION"].into_iter().filter_map(|key|environment.get(key).map(|v|(key.into(),v.clone()))).collect::<BTreeMap<_,_>>();
    let controls=["CARGO_TARGET_DIR","ANTIREA_RUST_UNIT_POLICY","RUSTC","RUSTC_WRAPPER"].into_iter().filter_map(|key|environment.get(key).map(|v|(key.into(),v.clone()))).collect::<BTreeMap<_,_>>();
    let diagnostics=diagnostic_environment(&environment);
    let start_time=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
    let unit=Path::new(p.get("record_root")).join(format!("{}-{start_time}",std::process::id()));
    fs::create_dir(&unit).map_err(|e|e.to_string())?;
    let mut forwarded_full=vec![p.get("backend").to_string()];forwarded_full.extend(forwarded.clone());
    let mut record=BTreeMap::new();
    for (key,value) in [("schema_version","1".to_string()),("mode",quote(p.get("mode"))),("kind",quote(&kind)),("cwd",quote(&text(&cwd)?)),("policy_sha256",quote(&p.sha)),("original_argv",array(&all)),("forwarded_argv",array(&forwarded_full)),("changes",format!("[{}]",changes.join(","))),("environment_sha256",quote(&env_sha)),("environment_digest_format",quote("uppercase-names-sorted-utf8-json-v1")),("environment_value_sha256",object(&env_hashes,false)),("control_environment",object(&controls,false)),("diagnostic_environment",object(&diagnostics,false)),("cargo_identity",object(&identity,false)),("consumed_inputs",object(&inputs,false)),("target_tree_before",target_before)] {record.insert(key.into(),value);}
    for key in ["backend","wrapper","linker"]{record.insert(key.into(),format!("{{\"path\":{},\"sha256\":{}}}",quote(p.get(key)),quote(p.get(&format!("{key}_sha256")))));}
    write_new(&unit.join("start.json"),object(&record,true).as_bytes())?;
    if Path::new(p.get("stop")).exists(){return Err("STOP set after record before compiler launch".into());}
    if target_tree(Path::new(p.get("target_root")))?!=record["target_tree_before"]{return Err("target alias inventory changed before launch".into());}
    // No shell. Preserve all accepted original arguments and exact captured
    // environment. stdout/stderr/stdin belong to Cargo and must not be intercepted.
    let began=Instant::now();let mut command=Command::new(p.get("backend"));
    let mut child=forward_environment(&mut command,&forwarded_environment).args(&forwarded).current_dir(&cwd).stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().map_err(|e|e.to_string())?;
    let mut cancelled=false;
    let status=loop {if Path::new(p.get("stop")).exists(){cancelled=true;let _=child.kill();break child.wait().map_err(|e|e.to_string())?;}if let Some(status)=child.try_wait().map_err(|e|e.to_string())?{break status;}thread::sleep(Duration::from_millis(100));};
    let target_after=target_tree(Path::new(p.get("target_root")))?;
    let mut changed=Vec::new();for (path,expected) in &inputs {let owned=Path::new(path).starts_with(Path::new(p.get("target_root")));if file_sha_inner(Path::new(path),owned).as_ref().ok()!=Some(expected){changed.push(path.clone());}}
    for key in ["backend","wrapper","linker"] {if tool_sha(Path::new(p.get(key)),key).as_ref().ok().map(String::as_str)!=Some(p.get(&format!("{key}_sha256"))){changed.push(key.into());}}
    if file_sha(&policy_path)?!=p.sha {changed.push("wrapper-policy".into());}
    let code=status.code().unwrap_or(1);let succeeded=code==0&&!cancelled&&changed.is_empty();
    let finish=format!("{{\"schema_version\":1,\"start_sha256\":{},\"compiler_pid\":{},\"compiler_exit_code\":{},\"cancelled\":{},\"milliseconds\":{},\"changed_inputs\":{},\"succeeded\":{},\"target_tree_after\":{},\"cleanup_scope\":\"direct compiler waited; outer Cargo Job must verify all descendants\"}}",quote(&file_sha(&unit.join("start.json"))?),child.id(),code,cancelled,began.elapsed().as_millis(),array(&changed),succeeded,target_after);
    write_new(&unit.join("finish.json"),finish.as_bytes())?;
    Ok(if succeeded{0}else if code!=0{code}else{1})
}
fn main(){match run(){Ok(code)=>std::process::exit(code),Err(error)=>{eprintln!("ANTI-REA trusted unit recorder: {error}");std::process::exit(101)}}}

#[cfg(test)] mod tests {
    use super::*;
    fn crate_args()->Vec<String>{["--crate-name","owned","--crate-type","rlib","--crate-type","cdylib","--target",TARGET,"--emit=dep-info,link","--out-dir","C:/owned/target","src/lib.rs"].into_iter().map(str::to_string).collect()}
    struct OwnedTemp(PathBuf);
    impl OwnedTemp{fn new()->Self{let path=env::temp_dir().join(format!("antirea-cargo-wrapper-test-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));fs::create_dir(&path).unwrap();Self(path)}}
    impl Drop for OwnedTemp{fn drop(&mut self){assert!(self.0.starts_with(env::temp_dir()));assert!(self.0.file_name().unwrap().to_str().unwrap().starts_with("antirea-cargo-wrapper-test-"));assert!(!fs::symlink_metadata(&self.0).unwrap().file_type().is_symlink());let _=fs::remove_dir_all(&self.0);}}
    #[test] fn sha_known_vectors(){assert_eq!(sha(b""),"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");assert_eq!(sha(b"abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");}
    #[test] fn sha_streaming(){let data=vec![b'a';1000000];assert_eq!(sha(&data),"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");let mut hash=Sha::new();for chunk in data.chunks(23){hash.update(chunk);}assert_eq!(hash.finish(),sha(&data));}
    #[test] fn json_escaping(){assert_eq!(quote("a\n\"\\\u{0}한"),"\"a\\n\\\"\\\\\\u0000한\"");}
    #[test] fn probes_unchanged(){let args=vec!["-vV".into()];let (_,kind,forward,changes)=derive(&args,"derivative").unwrap();assert_eq!(kind,"probe");assert_eq!(forward,args);assert!(changes.is_empty());}
    #[test] fn responses_rejected(){assert!(parse(&["@untracked.rsp".into()]).is_err());}
    #[test] fn custom_backend_link_args_and_library_rejected(){for arg in ["-Clink-arg=untrusted","-Ccodegen-backend=untrusted.dll","-loutside"]{assert!(parse(&[arg.into()]).is_err());}}
    #[test] fn exact_linker_required_for_crates_and_preserved(){let mut args=crate_args();args.extend(["-C".into(),"linker=C:/trusted/link.exe".into()]);let (rows,kind,forward,_)=derive(&args,"original").unwrap();validate_linker(&rows,&kind,"C:/trusted/link.exe").unwrap();assert_eq!(forward,args);let (_,_,derived,_)=derive(&args,"derivative").unwrap();assert!(derived.windows(2).any(|pair|pair[0]=="-C"&&pair[1]=="linker=C:/trusted/link.exe"));}
    #[test] fn missing_foreign_and_repeated_linkers_fail_closed(){let plain=crate_args();let (rows,kind)=parse(&plain).unwrap();assert!(validate_linker(&rows,&kind,"C:/trusted/link.exe").is_err());for suffix in [vec!["-Clinker=C:/foreign/link.exe"],vec!["-Clinker=C:/trusted/link.exe","-Clinker=C:/trusted/link.exe"]]{let mut args=plain.clone();args.extend(suffix.into_iter().map(str::to_string));let (rows,kind)=parse(&args).unwrap();assert!(validate_linker(&rows,&kind,"C:/trusted/link.exe").is_err());}}
    #[test] fn probe_linker_is_optional_but_exact_when_present(){for (suffix,valid) in [(vec![],true),(vec!["-Clinker=C:/trusted/link.exe"],true),(vec!["-Clinker=C:/foreign/link.exe"],false),(vec!["-Clinker=C:/trusted/link.exe","-Clinker=C:/trusted/link.exe"],false)]{let mut args=vec!["--print=cfg".to_string()];args.extend(suffix.into_iter().map(str::to_string));let (rows,kind)=parse(&args).unwrap();assert_eq!(validate_linker(&rows,&kind,"C:/trusted/link.exe").is_ok(),valid);}}
    #[test] fn repeated_library_kinds_preserve_tokens(){let args=crate_args();let (_,kind,forward,changes)=derive(&args,"original").unwrap();assert_eq!(kind,"crate");assert_eq!(forward,args);assert!(changes.is_empty());let (_,_,forward,_)=derive(&args,"derivative").unwrap();assert_eq!(forward.iter().filter(|x|x.as_str()=="--crate-type").count(),2);}
    #[test] fn invalid_or_duplicate_crate_types_rejected(){for kind in ["rlib","proc-macro","bin"]{let mut args=crate_args();args.extend(["--crate-type".into(),kind.into()]);assert!(parse(&args).is_err());}}
    #[test] fn absent_repeated_foreign_json_target_rejected(){let original=crate_args();let at=original.iter().position(|x|x=="--target").unwrap();let mut missing=original.clone();missing.drain(at..at+2);assert!(parse(&missing).is_err());let mut repeated=original.clone();repeated.extend(["--target".into(),TARGET.into()]);assert!(parse(&repeated).is_err());for target in ["aarch64-pc-windows-msvc","x86_64-unknown-linux-gnu","C:/outside/custom.json"]{let mut args=original.clone();args[at+1]=target.into();assert!(parse(&args).is_err());}}
    #[test] fn print_probe_target_value_count_checked(){assert!(parse(&["--print=cfg".into(),"--target".into(),TARGET.into()]).is_ok());assert!(parse(&["--print=cfg".into(),"--target=C:/outside/custom.json".into()]).is_err());assert!(parse(&["--print=cfg".into(),"--target".into(),TARGET.into(),"--target".into(),TARGET.into()]).is_err());}
    #[test] fn owned_target_hardlinks_are_accounted(){let tmp=OwnedTemp::new();let root=tmp.0.join("target");fs::create_dir(&root).unwrap();let first=root.join("first.rlib");let second=root.join("second.rlib");fs::write(&first,b"owned inert").unwrap();fs::hard_link(&first,&second).unwrap();assert_eq!(file_identity(&first).unwrap().1,2);let snapshot=target_tree(&root).unwrap();assert!(snapshot.contains("first.rlib")&&snapshot.contains("second.rlib"));assert!(check_path(&first).is_err());}
    #[test] fn outside_target_hardlink_refused_without_damage(){let tmp=OwnedTemp::new();let root=tmp.0.join("target");fs::create_dir(&root).unwrap();let sentinel=tmp.0.join("sentinel");fs::write(&sentinel,b"unchanged sentinel").unwrap();fs::hard_link(&sentinel,root.join("planted.dll")).unwrap();assert!(target_tree(&root).is_err());assert_eq!(fs::read(&sentinel).unwrap(),b"unchanged sentinel");}
    #[test] fn only_fixed_sdk_linker_allows_os_hardlinks(){let tmp=OwnedTemp::new();let linker=tmp.0.join("link.exe");fs::write(&linker,b"inert installed SDK fixture").unwrap();fs::hard_link(&linker,tmp.0.join("sdk-alias.exe")).unwrap();assert_eq!(tool_sha(&linker,"linker").unwrap(),sha(b"inert installed SDK fixture"));assert!(tool_sha(&linker,"backend").is_err());assert!(tool_sha(&linker,"wrapper").is_err());assert!(file_sha(&linker).is_err());}
    #[test] fn raw_device_unc_ads_paths_refused(){for value in [r"\\?\C:\owned\file",r"\\.\C:\owned\file",r"\\server\share\file",r"C:\owned\file:stream"]{assert!(check_path(Path::new(value)).is_err());}}
    #[test] fn forwarded_environment_preserves_case_unicode_and_controls_without_launch(){
        let values=vec![("Path".to_string(),"C:\\tools\\한글\\Ω".to_string()),
            ("MixedCase".to_string(),"line\nnext\tquote\"slash\\".to_string()),
            ("RUSTC".to_string(),"C:\\pinned\\rustc.exe".to_string()),
            ("ANTIREA_RUST_UNIT_POLICY".to_string(),"C:\\owned\\policy.txt".to_string())];
        let mut command=Command::new("never-launched.exe");command.env("OLD_EXPLICIT_SETTING","must disappear");
        forward_environment(&mut command,&values);
        let observed=command.get_envs().map(|(key,value)|(key.to_str().unwrap().to_string(),value.unwrap().to_str().unwrap().to_string())).collect::<BTreeMap<_,_>>();
        assert_eq!(observed,values.into_iter().collect::<BTreeMap<_,_>>());
        assert!(!observed.contains_key("OLD_EXPLICIT_SETTING"));
    }
    #[test] fn diagnostic_environment_filters_exact_fields_without_launch(){
        let mut environment=[("PATH","C:\\tools\\한글;C:\\other\\Ω"),
            ("CARGO_MAKEFLAGS","-j --jobserver-auth=observed\tcontrol\nvalue"),
            ("PRIVATE_TOKEN","secret-never-recorded"),("RUSTC","C:\\pinned\\rustc.exe")]
            .into_iter().map(|(key,value)|(key.to_string(),value.to_string())).collect::<BTreeMap<_,_>>();
        let before=environment.clone();let observed=diagnostic_environment(&environment);
        assert_eq!(observed.len(),2);
        for key in ["PATH","CARGO_MAKEFLAGS"]{assert_eq!(observed.get(key),environment.get(key));}
        assert_eq!(environment,before);
        assert!(!object(&observed,false).contains("secret-never-recorded"));
        assert!(!observed.contains_key("RUSTC"));
        environment.insert("PATH".into(),String::new());environment.remove("CARGO_MAKEFLAGS");
        let observed=diagnostic_environment(&environment);
        assert_eq!(observed.len(),1);assert_eq!(observed.get("PATH"),Some(&String::new()));
        assert!(!observed.contains_key("CARGO_MAKEFLAGS"));
    }
}

