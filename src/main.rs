use std::{ops::Shr, io::Write};

use openssl::bn::BigNum;

const E: u32 = 65537;

fn main() {
    let (p, q, n, e, d) = loop {
        let (p, q) = pick_p_and_q();
        println!("[RESULT] p = {}", p.to_dec_str().unwrap());
        println!("[RESULT] q = {}", q.to_dec_str().unwrap());

        let n = calc_n(&p, &q);
        println!("[RESULT] n = {}", n.to_dec_str().unwrap());

        let e = BigNum::from_u32(E).unwrap();
        println!("[RESULT] e = {}", e.to_dec_str().unwrap());

        let phi_n = calc_phi_n(&p, &q);
        println!("[RESULT] phi(n) = {}", phi_n.to_dec_str().unwrap());

        let d = calc_d(&phi_n, &e);
        let Some(d) = d else {
            println!("[INFO] phi(n) and e aren't coprime, trying again ...");
            continue;
        };
        println!("[RESULT] d = {}", d.to_dec_str().unwrap());

        print!("[INFO] verifying valid e and d ... ");
        for _ in 0..10 {
            let mut message = BigNum::new().unwrap();
            n.rand_range(&mut message).unwrap();

            let encrypted_message = encrypt(&message, &e, &n);
            let decrypted_message = decrypt(&encrypted_message, &d, &n);

            if message != decrypted_message {
                println!("[ERROR] expected message {}", message.to_dec_str().unwrap());
                println!("[ERROR] actual message   {}", decrypted_message.to_dec_str().unwrap());
                return;
            }
        }
        println!("e and d are valid!");

        break (p, q, n, e, d);
    };

    println!("{}", "=".repeat(40));
    println!("results:");
    println!("  p = {}", p.to_dec_str().unwrap());
    println!("  q = {}", q.to_dec_str().unwrap());
    println!("  n = {}", n.to_dec_str().unwrap());
    println!("  e = {}", e.to_dec_str().unwrap());
    println!("  d = {}", d.to_dec_str().unwrap());

    // read in message and encrypt it
    println!("{}", "=".repeat(40));
    let mut message = String::new();
    print!("[INPUT] Enter message to encrypt: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut message).unwrap();
    let message = BigNum::from_dec_str(&message).unwrap();

    println!();
    let encrypted_message = encrypt(&message, &e, &n);
    println!("[RESULT] encrypted message = {}", encrypted_message.to_dec_str().unwrap());

    // read in encrypted message and decrypt it
    println!();
    let mut message = String::new();
    print!("[INPUT] Enter message to decrypt: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut message).unwrap();
    let message = BigNum::from_dec_str(&message).unwrap();

    println!();
    let decrypted_message = decrypt(&message, &d, &n);
    println!("[RESULT] decrypted message = {}", decrypted_message.to_dec_str().unwrap());
}

fn pick_p_and_q() -> (BigNum, BigNum) {
    print!("[INFO] generating `p` and `q` with openssl ... ");

    let mut p = BigNum::new().unwrap();
    p.generate_prime(512, true, None, None).unwrap();

    let mut q = BigNum::new().unwrap();
    q.generate_prime(512, true, None, None).unwrap();

    println!("done!");

    (p, q)
}

fn calc_n(p: &BigNum, q: &BigNum) -> BigNum {
    print!("[INFO] calculating n = p * q ... ");
    let n = p * q;
    println!("done!");

    n
}

fn calc_phi_n(p: &BigNum, q: &BigNum) -> BigNum {
    print!("[INFO] calculating phi(n) = (p - 1) * (q - 1) ... ");
    let one = BigNum::from_u32(1).unwrap();
    let phi_n = &(p - &one) * &(q - &one);
    println!("done!");

    phi_n
}

fn calc_d(phi_n: &BigNum, e: &BigNum) -> Option<BigNum> {
    let zero = BigNum::from_u32(0).unwrap();

    println!("[INFO] calculating d with extended euclidean algorithm ...");
    let d = extended_euclidean(&phi_n, &e);
    println!("[INFO] finished calculating d!");

    d.map(|d| if d.0 < zero {
        &d.0 + phi_n
    } else {
        d.0
    })
}

fn extended_euclidean(a: &BigNum, b: &BigNum) -> Option<(BigNum, BigNum)> {
    let zero = BigNum::from_u32(0).unwrap();
    let one = BigNum::from_u32(1).unwrap();

    println!("  a = b*k + r");
    let k = a / b;
    let r = a % b;

    println!("    a = {}", a.to_dec_str().unwrap());
    println!("    b = {}", b.to_dec_str().unwrap());
    println!("    k = {}", k.to_dec_str().unwrap());
    println!("    r = {}", r.to_dec_str().unwrap());

    if r == zero {
        println!("  found r = 0 and b != 1, phi(n) and e aren't coprime");
        return None;
    }
    if r == one {
        println!("  found r = 1, phi(n) and e are coprime");
        return Some((-k, one));
    }
    
    let (k1, k2) = extended_euclidean(&b, &r)?;

    println!("  1 = k1*(b*(-k) + a) + k2*b = k3*b + k1*a WHERE k3 = k1*(-k) + k2");
    let k3 = &(&k1 * &(-&k)) + &k2;
    println!("    a = {}", a.to_dec_str().unwrap());
    println!("    b = {}", b.to_dec_str().unwrap());
    println!("    k = {}", k.to_dec_str().unwrap());
    println!("    k1 = {}", k1.to_dec_str().unwrap());
    println!("    k2 = {}", k2.to_dec_str().unwrap());
    println!("    k3 = {}", k3.to_dec_str().unwrap());

    Some((k3, k1))
}

fn encrypt(m: &BigNum, e: &BigNum, n: &BigNum) -> BigNum {
    g_pow_a_mod_p(m, e, n)
}

fn decrypt(m: &BigNum, d: &BigNum, n: &BigNum) -> BigNum {
    g_pow_a_mod_p(m, d, n)
}


fn g_pow_a_mod_p(g: &BigNum, a: &BigNum, p: &BigNum) -> BigNum {
    let mut a = a.as_ref().to_owned().unwrap();
    let mut power = g.as_ref().to_owned().unwrap();
    let mut result = BigNum::from_u32(1).unwrap();
    
    let zero = BigNum::from_u32(0).unwrap();

    loop {
        if a == zero {
            break result;
        }

        if a.is_bit_set(0) {
            result = &(&result * &power) % p;
        }

        a = a.shr(1);
        power = &(&power * &power) % p;
    }
}
