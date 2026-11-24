use super::*;

// Execution choices only. All three evaluate the same statement and emit the same field elements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum PowerKernel {
    Reference,
    Wide,
    Radix,
}
pub(super) fn selected_power_kernel(method: u8, table: bool) -> PowerKernel {
    if method != BLOCK_POWER_METHOD {
        return PowerKernel::Reference;
    }
    if table {
        PowerKernel::Wide
    } else {
        PowerKernel::Radix
    }
}
// Exact radix-2^64 accumulation. Each sum is strictly below
// (2^64)(2^31)(2^32) = 2^127 even for signed i32::MIN and u32::MAX blocks.
// Reducing one signed coefficient per limb costs O(output size), independent of block count.
pub(super) fn wide_sum<T: Copy + Into<i64> + Sync>(
    slices: &[&[T]],
    weights: &[[u64; 4]],
    out: &mut [Scalar],
    offset: usize,
) {
    let mut acc = vec![[0i128; 4]; out.len()];
    for (&row, digits) in slices.iter().zip(weights) {
        let tail = row.get(offset..).unwrap_or(&[]);
        for (sum, &value) in acc.iter_mut().zip(tail) {
            let x = i128::from(value.into());
            for k in 0..4 {
                sum[k] += x * i128::from(digits[k]);
            }
        }
    }
    for (dst, coeffs) in out.iter_mut().zip(acc) {
        *dst = reduce_signed_digits(&coeffs);
    }
}
// Pack the exact two's-complement sum into 320 bits, then reduce its magnitude once.
pub(super) fn reduce_signed_digits<T: Copy + Into<i128>, const N: usize>(
    coeffs: &[T; N],
) -> Scalar {
    let bytes = 32 / N;
    let mut encoded = [0u8; 64];
    let mut carry = 0i128;
    for (word, &k) in encoded[..32].chunks_exact_mut(bytes).zip(coeffs) {
        let x = k.into() + carry;
        word.copy_from_slice(&x.to_le_bytes()[..bytes]);
        carry = x >> (bytes * 8);
    }
    encoded[32..40].copy_from_slice(
        &i64::try_from(carry)
            .expect("bounded high limb")
            .to_le_bytes(),
    );
    if carry < 0 {
        let mut one = true;
        for b in &mut encoded[..40] {
            let (v, c) = (!*b).overflowing_add(u8::from(one));
            *b = v;
            one = c;
        }
        -Scalar::from_bytes_mod_order_wide(&encoded)
    } else {
        Scalar::from_bytes_mod_order_wide(&encoded)
    }
}
// Narrow digit products fit in i64, including negative entries. Flush every 32768
// blocks so both u32 * i16 and u16 * i32 stay strictly below 2^63 in magnitude.
pub(super) fn radix_sum<T: Copy + Into<i64> + Sync, const N: usize>(
    slices: &[&[T]],
    weights: &[[u32; N]],
    out: &mut [Scalar],
    offset: usize,
) {
    for (rows, digits) in slices.chunks(32768).zip(weights.chunks(32768)) {
        let mut acc = vec![[0i64; N]; out.len()];
        for (&row, w) in rows.iter().zip(digits) {
            for (s, &v) in acc.iter_mut().zip(row.get(offset..).unwrap_or(&[])) {
                let x = v.into();
                for k in 0..N {
                    s[k] += x * i64::from(w[k]);
                }
            }
        }
        for (dst, coeffs) in out.iter_mut().zip(acc) {
            *dst += reduce_signed_digits(&coeffs);
        }
    }
}
pub(super) fn wide_digits(ws: &[Scalar]) -> Vec<[u64; 4]> {
    ws.iter()
        .map(|w| {
            std::array::from_fn(|i| {
                u64::from_le_bytes(w.as_bytes()[8 * i..8 * i + 8].try_into().unwrap())
            })
        })
        .collect()
}
pub(super) fn narrow_digits<const N: usize>(ws: &[Scalar]) -> Vec<[u32; N]> {
    let bytes = 32 / N;
    ws.iter()
        .map(|w| {
            std::array::from_fn(|i| {
                let mut a = [0u8; 4];
                a[..bytes].copy_from_slice(&w.as_bytes()[bytes * i..bytes * (i + 1)]);
                u32::from_le_bytes(a)
            })
        })
        .collect()
}
pub(super) fn power_witness(
    w: &FairWork,
    c: &FairCase,
    ws: &[Scalar],
    mode: PowerKernel,
) -> Vec<Scalar> {
    if mode == PowerKernel::Reference {
        return fair_a(w, c, ws);
    }
    let d = usize::from(w.request.query.dimension);
    let rows: Vec<_> = c
        .blocks
        .iter()
        .map(|b| &w.documents[b.doc][b.offset * d..(b.offset + b.len) * d])
        .collect();
    let mut out = vec![Scalar::ZERO; c.h * d];
    let tile = out
        .len()
        .div_ceil(rayon::current_num_threads() * 3)
        .clamp(1, 128);
    if mode == PowerKernel::Wide {
        let digits = wide_digits(ws);
        out.par_chunks_mut(tile)
            .enumerate()
            .for_each(|(i, v)| wide_sum(&rows, &digits, v, i * tile));
    } else {
        let digits = narrow_digits::<8>(ws);
        out.par_chunks_mut(tile)
            .enumerate()
            .for_each(|(i, v)| radix_sum(&rows, &digits, v, i * tile));
    }
    out
}
pub(super) fn power_table(
    w: &FairWork,
    c: &FairCase,
    ws: &[Scalar],
    mode: PowerKernel,
) -> Vec<Scalar> {
    if mode == PowerKernel::Reference {
        return fair_y(w, c, ws);
    }
    let m = usize::from(w.request.query.token_count);
    let wide = if mode == PowerKernel::Wide {
        wide_digits(ws)
    } else {
        vec![]
    };
    let narrow = if mode == PowerKernel::Radix {
        narrow_digits::<16>(ws)
    } else {
        vec![]
    };
    let mut out = vec![Scalar::ZERO; m * c.h];
    out.par_chunks_mut(c.h).enumerate().for_each(|(j, v)| {
        let rows: Vec<_> = c
            .blocks
            .iter()
            .map(|b| {
                let (_, n, y) = &w.matrices[b.doc];
                let start = j * n + b.offset;
                &y[start..start + b.len]
            })
            .collect();
        if mode == PowerKernel::Wide {
            wide_sum(&rows, &wide, v, 0);
        } else {
            radix_sum(&rows, &narrow, v, 0);
        }
    });
    out
}
pub(super) fn geometric_sequence(z: Scalar, n: usize, parallel: bool) -> Vec<Scalar> {
    if !parallel || n < 512 {
        let mut out = Vec::with_capacity(n);
        let mut weight = Scalar::ONE;
        for _ in 0..n {
            out.push(weight);
            weight *= z;
        }
        return out;
    }
    let mut out = vec![Scalar::ZERO; n];
    let fill = |chunk: &mut [Scalar], first: Scalar| {
        let mut next = first;
        for dst in chunk {
            *dst = next;
            next *= z;
        }
    };
    const CHUNK: usize = 128;
    let jump = (0..CHUNK.ilog2()).fold(z, |x, _| x * x);
    let mut starts = vec![Scalar::ONE; n.div_ceil(CHUNK)];
    let mut first = Scalar::ONE;
    for start in &mut starts {
        *start = first;
        first *= jump;
    }
    out.par_chunks_mut(CHUNK)
        .zip(starts)
        .for_each(|(chunk, start)| fill(chunk, start));
    out
}
