use statrs::distribution::{Binomial, Discrete, DiscreteCDF, Hypergeometric};

pub fn calc() {

    let n = Hypergeometric::new(1_000_000, 333_333, 128).unwrap().sf(86);
    println!("n: {}", n);


    let mut highest = 0.0;
    let mut at_highest = 4;


    let n2 = Hypergeometric::new(1_000_000, 333_333, 16).unwrap().pmf(16);
    println!("n2: {}", n2);

    let n3 = Binomial::new(1.0/8.0, 128).unwrap().sf(15);
    println!("n3: {}", n3);


    // 0.5399482343860837 chance 16 or more are picked.

    for i in 4..(16+1) {
        let n2 = 1.0-Hypergeometric::new(1_000_000, 333_333, i).unwrap().pmf(i);

        // Everyone has a percentage chance to be a leader.
        // Given 128, everyone has 128/16 = 1/8 chance to be a leader.
        // Given 128 trials, what's the chance to get at least x leaders.
        let n3 = Binomial::new(1.0/6.4, 128).unwrap().sf(i-1);

        if n3*n2 > highest {
            highest = n3 * n2;
            at_highest = i;
        }
    }

    println!("Highest value: {} {}", highest, at_highest);

    let mut sum = 0.0;

    for i in 1..(128+1) {
        let n2;
        if i != 0 {
            n2 = Hypergeometric::new(1_000_000, 333_333, i).unwrap().pmf(i);
        } else {
            n2 = 1.0;
        }

        if n2 <= 0.0 {
            break;
        }

        // Everyone has a percentage chance to be a leader.
        // Given 128, everyone has 128/16 = 1/8 chance to be a leader.
        // Given 128 trials, what's the chance to get at least x leaders.
        let n3 = Binomial::new(1.0/8.0, 128).unwrap().pmf(i);

        sum += n2*n3;
    }

    let x = Binomial::new(1.0/8.0, 128).unwrap().pmf(16);

    println!("sum: {}", sum);

    let fin = 1.0-(1.0-sum).powf(64.0*7200.0);
    println!("final {}", fin);


    let last = Binomial::new(1.0/8.0, 128).unwrap().pmf(0);
    println!("last: {}", last);
    //256

    sum = 0.0;
    for i in 1..(128+1) {
        let threshold = ((i as f64) / 2.0).floor() as u64 + 1;
        let n2;
        if i != 0 {
            n2 = 1.0 - Hypergeometric::new(1_000_000, 333_333, i).unwrap().cdf(threshold.max(1)-1);
        } else {
            n2 = 1.0;
        }

        if n2 <= 0.0 {
            continue;
        }

        // Everyone has a percentage chance to be a leader.
        // Given 128, everyone has 128/16 = 1/8 chance to be a leader.
        // Given 128 trials, what's the chance to get at least x leaders.
        let n3 = Binomial::new(1.0/8.0, 128).unwrap().pmf(i);

        sum += n2*n3;
    }
    println!("sum2: {}", sum);
}
