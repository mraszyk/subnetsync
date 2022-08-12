use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use ic_agent::{Agent, Certificate, hash_tree::Label, hash_tree::LookupResult, ic_types::Principal};

pub fn lookup_value<'a, P>(
    certificate: &'a Certificate<'a>,
    path: P,
) -> Result<&'a [u8], ic_agent::AgentError>
where
    for<'p> &'p P: IntoIterator<Item = &'p Label>,
    P: Into<Vec<Label>>,
{
    use ic_agent::AgentError::*;
    match certificate.tree.lookup_path(&path) {
        LookupResult::Absent => Err(LookupPathAbsent(path.into())),
        LookupResult::Unknown => Err(LookupPathUnknown(path.into())),
        LookupResult::Found(value) => Ok(value),
        LookupResult::Error => Err(LookupPathError(path.into())),
    }
}

async fn check(agent: &ic_agent::agent::Agent, canister_id_str: String, subnet_id_str: String) {
    let can_id = Principal::from_text(canister_id_str).unwrap();
    let subnet_id = Principal::from_text(subnet_id_str).unwrap();
    let paths: Vec<Vec<Label>> = vec![vec!["time".into()]];
    let path_time: Vec<Label> = vec!["time".into()];
    let cert = agent.read_state_raw(paths, can_id, false).await.unwrap();
    let t_ic_uleb128: &[u8] = lookup_value(&cert, path_time).unwrap();
    let t_ic = leb128::read::unsigned(&mut t_ic_uleb128.clone()).unwrap();
    let t_real = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    match cert.delegation {
      None => {println!("no_delegation");}
      Some(x) => {
        let d: Certificate = serde_cbor::from_slice(&x.certificate).unwrap();
        let path_ran: Vec<Label> = vec!["subnet".into(), subnet_id.into(), "canister_ranges".into()];
        let ran: &[u8] = lookup_value(&d, path_ran).unwrap();
        let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(ran).unwrap();
        println!("   delegation: {:?} {:?}", ranges[0].0.to_text(), ranges[0].1.to_text());
      }
    }
    println!("      IC time: {:?}", t_ic);
    println!("physical time: {:?}", t_real);
    println!("diff: {:+.2e} s", ((t_real as f64)-(t_ic as f64))*1.00e-9);
    println!("");
}

#[tokio::main]
async fn main() {
  let regsnap_cmd = Command::new("./ic-regedit")
    .args(["canister-snapshot", "--url", "https://[2a00:fb01:400:100:5000:ceff:fea2:bb0]:8080"])
    .output()
    .unwrap();
  let regsnap_str = String::from_utf8(regsnap_cmd.stdout).unwrap();
  let json: serde_json::Value = serde_json::from_str(&regsnap_str).unwrap();
  let table = json.get("routing_table").unwrap().get("entries").unwrap().as_array().unwrap();
  let agent = Agent::builder()
    .with_transport(
      ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport::create("https://ic0.app/").unwrap(),
    )
    .build().unwrap();
  for x in table {
    let subnet_id = x.get("subnet_id").unwrap().get("principal_id").unwrap().get("raw").unwrap().as_str().unwrap().strip_prefix("(principal-id)").unwrap();
    let start_canister_id = x.get("range").unwrap().get("start_canister_id").unwrap().get("principal_id").unwrap().get("raw").unwrap().as_str().unwrap().strip_prefix("(principal-id)").unwrap();
    let end_canister_id = x.get("range").unwrap().get("end_canister_id").unwrap().get("principal_id").unwrap().get("raw").unwrap().as_str().unwrap().strip_prefix("(principal-id)").unwrap();
    println!("routing_table: {:?} {:?}", start_canister_id, end_canister_id);
    check(&agent, start_canister_id.into(), subnet_id.into()).await;
  }
}
