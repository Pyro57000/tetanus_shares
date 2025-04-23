use ldap3::{LdapConn, LdapConnAsync, Scope, SearchEntry};
use ldap3::result::Result;
use ldap3::Ldap;
use clap::{error, Parser};
use std::fmt::Debug;
use std::process::exit;
use std::future::Future;

#[derive(Parser, Debug)]
#[command(version, about, long_about = Some("finds shares, but its written in rust which sometimes gets past EDR!"))]
struct Args{
    #[arg(short, long)]
    domain: String,

    #[arg(short, long)]
    kdc: String,

    #[arg(short, long, default_value_t = String::from("none"))]
    user: String,

    #[arg(short, long, default_value_t = String::from("none"))]
    password: String,
}
async fn search(dc: String, url: String, dn: String){
    println!("DC: {}", &dc);
    println!("URL: {}", &url);
    println!("DN: {}", &dn);
    let mut con_res = LdapConnAsync::new(&url).await;
    if con_res.is_err(){
        let error = con_res.err().unwrap();
        println!("error setting up connection!");
        println!("{}", error);
        return;
    }
    let (conn, mut ldap) = con_res.unwrap();
    Ldap::sasl_gssapi_bind(&mut ldap, &dc).await;
    ldap3::drive!(conn);
    let search_res = ldap.search(&dn, Scope::Subtree, "objectClass=share", vec![""]).await;
    if search_res.is_err(){
        let error = search_res.err().unwrap();
        println!("error running search!");
        println!("{}", error);
        return;
    }
    let rs = search_res.unwrap();
    let results = rs.success().unwrap();
    for entry in results.0{
        println!("{}", SearchEntry::construct(entry).dn);
    }
    ldap.unbind().await;
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut existing_con = true;
    if args.user != "none".to_owned(){
        existing_con = false;
        if args.password == "none".to_owned(){
            println!("if you're supplying a user, we need a password bud!");
            exit(1);
        }
    }
    let domain_controller = format!("{}.{}", args.kdc, args.domain);
    let ldap_url = format!("ldap://{}", &domain_controller);
    let domain_parts: Vec<&str> = args.domain.split(".").collect();
    let mut domain_string = format!("dc={}", args.domain);
    if domain_parts.len() > 1{
        domain_string.clear();
        for part in domain_parts{
            let part_string = format!("dc={},", part);
            domain_string.push_str(&part_string);
        }
        domain_string.pop();
    }
    search(domain_controller, ldap_url, domain_string).await;
}
