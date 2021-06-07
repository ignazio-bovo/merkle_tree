// implementation test for 
use codec::{Encode, Decode};
use sp_runtime::traits::{Hash, BlakeTwo256};
use sp_core::{
	H256,
};

fn merkle_path(len: usize, index: usize) -> Vec<Option<usize>> {//Result<Vec<usize>, &'static str>{
    let mut idx = index;
    assert!(idx > 0);
    let floor_2 = |x: usize| { (x >> 1) + (x % 2) };
    let mut path = Vec::new();
    let mut prev_len : usize = 0;
    let mut el = len;
    while el != 1 {
        if idx % 2 == 1 && idx == el { path.push(None); }
        else {
            if idx % 2 == 1 { path.push(Some(prev_len + idx + 1)) }
            else { path.push( Some(prev_len + idx - 1) ) }
        }
        prev_len += el;
        idx = floor_2(idx);
        el = floor_2(el);

    }
    return path;
}

#[test] 
fn test_merkle_path_4() {
    let out = merkle_path(5, 4);
    assert_eq!(out, [Some(3), Some(6), Some(10)]);
}
#[test] 
fn test_merkle_path_1() {
    let out = merkle_path(5, 1);
    assert_eq!(out, [Some(2), Some(7), Some(10)]);
}
#[test] 
fn test_merkle_path_5() {
    let out = merkle_path(5, 5);
    assert_eq!(out, [None, None, Some(9)]);
}

fn gen_proof_(b: &Vec<i32>) -> Result<Vec<H256>, &'static str>{
    if b.len() == 0 {
        return Err("empty vector");
    }
    let mut out = Vec::new();
    for e in b.iter() {
        out.push(BlakeTwo256::hash_of(&e));
    }

    let mut start: usize = 0;
    let mut last_len = out.len();
    let mut new_len = out.len();
    let mut max_len = last_len >> 1;
    let mut rem = last_len % 2;

    // range [last...(maxlen >> 1) + (maxlen % 2)]
    while max_len != 0 {
        last_len = out.len();
        for i in 0..max_len {
            out.push(BlakeTwo256::hash_of(&[out[start + 2*i],out[start + 2*i + 1]]));
        }
        if rem == 1 {
            out.push(BlakeTwo256::hash_of(&out[last_len-1]));
        }
        new_len = (out.len() - last_len);
        rem = new_len % 2;
        max_len = new_len >> 1;
        start = last_len;
    }
    //let l = out.len();
    //assert_eq!(BlakeTwo256::hash_of(&[out[l-3], out[l-2]]), out[l-1]);
    Ok(out)
}

fn gen_proof(b: &Vec<u64>) -> Vec<u64>{
    let mut out = Vec::new();
    for e in b.iter() {
        out.push(*e);
    }

    let mut start: usize = 0;
    let mut last_len = out.len();
    let mut new_len = out.len();
    let mut max_len = last_len >> 1;
    let mut rem = last_len % 2;

    // range [last...(maxlen >> 1) + (maxlen % 2)]
    while max_len != 0 {
        last_len = out.len();
        for i in 0..max_len {
            out.push(out[start + 2*i]+out[start + 2*i + 1]);
        }
        if rem == 1 {
            out.push(out[last_len-1]);
        }
        new_len = (out.len() - last_len);
        rem = new_len % 2;
        max_len = new_len >> 1;
        start = last_len;
    }
    let l = out.len();
    assert_eq!(out[l-2]+ out[l-3], out[l-1]);
    return out;
}

#[test]
fn test_gen_proof() {
    let b: Vec<u64> = vec![1,2,3,4];
    assert_eq!(gen_proof(&b), [1,2,3,4,3,7,10]);

}

fn verify_proof(path: &[Option<H256>],    
                         value: i32, i: usize, root: H256) -> Result<bool, &'static str> 
{
  let exp = path.len() - 1;
  if i > 2usize.checked_pow(exp as u32).ok_or("index overflow")? {                  
      return Err("index out of range or Merkle path insufficient for validation");
  } else {                                                                            
      let mut idx = i.checked_add(1).ok_or("index overflow")?; 
      let mut hash_value = BlakeTwo256::hash_of(&value); 
      for h_el in path.iter() {
          hash_value = match h_el {
              Some(h) => {
                  if idx % 2 == 1 {
                      BlakeTwo256::hash_of(&[hash_value, *h])
                  } else {                                                                      
                      BlakeTwo256::hash_of(&[*h, hash_value])                          
                  }                                                                             
              },                                                                                
              None => {                                                                         
                  BlakeTwo256::hash_of(&hash_value)                                    
              },                                                                                
          };                                                                                    
          idx = (idx >> 1) + idx.wrapping_rem(2);                                               
      }                                                                                         
      let ans = root == hash_value; 
      return Ok(ans);
  }
}

fn helper_build_merkle_path(b: &[i32], idx: usize, out: &[H256]) -> Vec<Option<H256>>
{
    let path = merkle_path(b.len(), idx+1);
    let mut merkle_proof: Vec<Option<H256>> = Vec::new();
    for el_ in path.iter() {
        match el_ {
            Some(i) => {
                merkle_proof.push(Some(out[*i - 1]));
            },
            None => merkle_proof.push(None),
        }
    }
    return merkle_proof;
}
#[test]
fn elements_belong_to_collection_size_power_of_two() {
    let b = vec![1,2,3,4];
    let idx: usize =  1;
    let value = 2;
    let out = gen_proof_(&b).unwrap();
    let merkle_proof = helper_build_merkle_path(&b, idx, &out);
    let root = out.last().copied().unwrap();
    //println!("proof: {:?}", merkle_proof);
    match verify_proof(&merkle_proof, value, idx, root) {
        Ok(ans) => assert_eq!(ans, true),
        Err(msg) => panic!(msg)
    }
}

#[test]
fn elements_belong_to_collection_even() {
    let b = vec![1,2,3,4,5,6];
    let idx: usize =  1;
    let value = 2;
    let out = gen_proof_(&b).unwrap();
    let merkle_proof = helper_build_merkle_path(&b, idx, &out);
    let root = out.last().copied().unwrap();
    //println!("proof: {:?}", merkle_proof);
    match verify_proof(&merkle_proof, value, idx, root) {
        Ok(ans) => assert_eq!(ans, true),
        Err(msg) => panic!(msg)
    }
}
#[test]
fn elements_belong_to_collection_odd() {
    let b = vec![1,2,3,4,5];
    let idx: usize =  1;
    let value = 2;
    let out = gen_proof_(&b).unwrap();
    let merkle_proof = helper_build_merkle_path(&b, idx, &out);
    let root = out.last().copied().unwrap();
    //println!("proof: {:?}", merkle_proof);
    match verify_proof(&merkle_proof, value, idx, root) {
        Ok(ans) => assert_eq!(ans, true),
        Err(msg) => panic!(msg)
    }
}

fn main() {}

