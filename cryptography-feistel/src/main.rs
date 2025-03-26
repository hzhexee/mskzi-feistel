
fn vec_xor(vec1: Vec<u8>, vec2: Vec<u8>)  -> Vec<u8> {
    let mut res = Vec::new();
    for (i, j) in vec1.iter().zip(vec2.iter()) {
        res.push(i ^ j);
    }
    res
}

fn vec_invert(vect: Vec<u8>) -> Vec<u8>{
    vect.iter().map(|x| !x).collect::<Vec<u8>>()
}

fn bit_left(vect: Vec<u8>) -> Vec<u8>{
    vect.iter().map(|x| x << 1).collect::<Vec<u8>>()
}


fn permute_word(mut word: Vec<u8>, key: u8) -> Vec<u8>{
    for i in 0..word.len() {
        let new_index = (i + key as usize) % word.len();
        word.swap(i, new_index);
    }
    word
}

fn f(right: Vec<u8>, key: Vec<u8>) -> Vec<u8>{
    bit_left(vec_invert(vec_xor(right, key)))
}

fn keys_gen(key: Vec<u8>, decrypt: bool, rounds: u8) -> Vec<Vec<u8>>{
    let mut res:Vec<Vec<u8>> = Vec::new();
    for i in 0..rounds {
        res.push(permute_word(key.clone(), i));
    }
   
    if decrypt == true {
        res.reverse();
    }
    res
}

fn crypt_round(block: Vec<u8>, round_key: Vec<u8>) -> Vec<u8>{
    let left = block[0..block.len()/2].to_vec();
    let right = block[block.len()/2..block.len()].to_vec();
    let new_right = vec_xor(left, f(right.clone(), round_key));
    [right, new_right].concat()
}

fn crypt_block(mut block: Vec<u8>, key: Vec<u8>, decrypt:bool, rounds:u8) -> Vec<u8>{
    let keys = keys_gen(key, decrypt, rounds);
    for round_key in keys{
        block = crypt_round(block, round_key);
    }
    let left = block[0..block.len()/2].to_vec();
    let right = block[block.len()/2..block.len()].to_vec();
    [right, left].concat()
}

fn main(){
    let block: Vec<u8> = "budapesh".as_bytes().to_vec();
    let key: Vec<u8> = "rust".as_bytes().to_vec();
    let rounds:u8 = 10;
    let encrypt: Vec<u8> = crypt_block(block.clone(), key.clone(), false, rounds);
    let decrypt: Vec<u8> = crypt_block(encrypt.clone(), key.clone(), true, rounds);
    println!("{:?}", block);
    println!("{:?}", encrypt);
    println!("{:?}", decrypt)
}