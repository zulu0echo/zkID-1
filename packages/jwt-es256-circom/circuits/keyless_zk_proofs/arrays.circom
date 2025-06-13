pragma circom 2.1.3;

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";
include "./hashtofield.circom";
include "./misc.circom";

// Outputs a bit array where indices [start_index, end_index) (inclusive of start_index, exclusive of end_index) are all 1, and all other bits are 0.
// If end_index >= len, returns a bit array where start_index and all indices after it are 1, and all other bits are 0.
template ArraySelector(len) {
    signal input start_index;
    signal input end_index;
    signal input enabled;
    signal output out[len];

    var start_less_than_end = LessThan(20)([start_index, end_index]);
    AssertEqualIfTrue()([start_less_than_end,1],enabled);

    signal start_selector[len] <== SingleOneArray(len)(start_index, enabled);
    signal end_selector[len] <== SingleNegOneArray(len)(end_index, enabled);

    out[0] <== start_selector[0];
    for (var i = 1; i < len; i++) {
        out[i] <== out[i-1] + start_selector[i] + end_selector[i];
    }
}

// Similar to ArraySelector, but works when end_index > start_index is not satisfied, in which
// case an array of all 0s is returned. Does NOT work when start_index is 0
template ArraySelectorComplex(len) {
    signal input start_index;
    signal input end_index;
    signal input enabled;

    signal output out[len];
    signal should_fail <== IsEqual()([start_index, 0]);
    AssertEqualIfTrue()([should_fail,0], enabled);

    signal right_bits[len] <== RightArraySelector(len)(start_index-1, enabled);
    signal left_bits[len] <== LeftArraySelector(len)(end_index, enabled);

    for (var i = 0; i < len; i++) {
        out[i] <== right_bits[i] * left_bits[i]; 
    }
}

// Outputs a bit array where all bits to the right of `index` are 0, and all other bits including `index` are 1
// Assumes that 0 <= index < len, and that len > 1
template LeftArraySelector(len) {
    signal input index;
    signal input enabled;
    signal output out[len];

    // SingleOneArray will fail if index >= len
    signal bits[len] <== SingleOneArray(len)(index, enabled);
    var sum = 0;
    for (var i = 0; i < len; i++) {
        sum = sum + bits[i];
    }

    out[len-1] <== 1 - sum;
    for (var i = len-2; i >= 0; i--) {
        out[i] <== out[i+1] + bits[i+1];
    }
}

// Outputs a bit array where all bits to the left of `index` are 0, and all other bits are 1 including `index`
// Assumes that 0 <= index < len
template RightArraySelector(len) {
    signal input index;
    signal input enabled;
    signal output out[len];

    // SingleOneArray fails if index >= len
    signal bits[len] <== SingleOneArray(len)(index, enabled);

    out[0] <== 0;
    for (var i = 1; i < len; i++) {
        out[i] <== out[i-1] + bits[i-1];
    }
}

// Given two input arrays `in1` and `in2` each of length `len`, outputs
// an array `out` that is the same length, which is the elementwise multiplication of
// `in1` and `in2`
// WARNING: This could cause integer overflow if the product of any two multiplied elements exceeds the field modulus
template ElementwiseMul(len) {
    signal input in1[len];
    signal input in2[len];
    signal output out[len];

    for (var i = 0; i < len; i++) {
        out[i] <== in1[i] * in2[i];
    }
}

// Given an array of integers `in` of all 1s and 0s, returns an array `out` where
// each 1 is now 0 and each 0 is now 1
// Assumes `in` contains only 1s and 0s
template InvertBinaryArray(len) {
    signal input in[len];
    signal output out[len];

    for (var i = 0; i < len; i++) {
        out[i] <== 1 - in[i];
    }
}

// Similar to Decoder template from circomlib/circuits/multiplexer.circom
// Returns a bit array `out` with a 1 at index `index`, and 0s everywhere else
// Assumes that 0 <= index < len
template SingleOneArray(len) {
    signal input index;
    signal input enabled;

    signal output out[len];
    signal success;
    var lc = 0;

    for (var i = 0; i < len; i++) {
        out[i] <-- (index == i) ? 1 : 0;
        // Enforces that either out[i] is 0, or index = i
        out[i] * (index-i) === 0;
        lc = lc + out[i];
    }
    lc ==> success;
    // support array sizes up to a million with the `GreaterEqThan` 20 parameter. Being conservative here b/c according to Michael this template is very cheap
    signal should_be_all_zeros <== GreaterEqThan(20)([index, len]);
    // Enforces that `lc` is equal to 1 if len < index

    AssertEqualIfTrue()([success, 1 * (1 - should_be_all_zeros)], enabled);
    AssertEqualIfTrue()([should_be_all_zeros,0], enabled);
}

// Given an array 'arr', returns the value at index `index`
// Assumes that 0 <= index < len
template SelectArrayValue(len) {
    signal input arr[len];
    signal input index;
    signal input enabled;
    signal output out;

    signal selector[len] <== SingleOneArray(len)(index,enabled);

    out <== EscalarProduct(len)(arr, selector);
}

// Similar to Decoder template from circomlib/circuits/multiplexer.circom
// Returns a bit array `out` with a -1 at index `index`, and 0s everywhere else
// Returns an array of all 0s if it is not the case that 0 <= index < len
// TODO: Rename this to make returning all 0s when out of bounds more clear
template SingleNegOneArray(len) {
    signal input index;
    signal input enabled;
    signal output out[len];
    signal success;
    var lc = 0;

    for (var i = 0; i < len; i++) {
        out[i] <-- (index == i) ? -1 : 0;
        out[i] * (index-i) === 0;
        lc = lc + out[i];
    }
    lc ==> success;
    // support array sizes up to a million. Being conservative here b/c according to Michael this template is very cheap
    signal should_be_all_zeros <== GreaterEqThan(20)([index, len]);
    success === -1 * (1 - should_be_all_zeros);
}

// Checks that `substr` of length `substr_len` matches `str` beginning at `start_index`
// Assumes `random_challenge` is computed by the Fiat-Shamir transform
// Takes in hash of the full string as an optimization, to prevent it being hashed 
// multiple times if the template is invoked on that string more than once, which
// is very expensive in terms of constraints
// Assumes that:
// - `str_hash` is the hash of `str`
// - `substr` is 0-padded after `substr_len` characters
// Enforces that:
// - `str[start_index:substr_len]` = `substr[0:substr_len]`
template CheckSubstrInclusionPoly(maxStrLen, maxSubstrLen) {
    signal input str[maxStrLen];
    signal input str_hash;
    signal input substr[maxSubstrLen];
    signal input substr_len;
    signal input start_index;
    signal input enabled;

    signal substr_hash <== HashBytesToFieldWithLen(maxSubstrLen)(substr, substr_len);
    signal random_challenge <== Poseidon(4)([str_hash, substr_hash, substr_len, start_index]);

    signal challenge_powers[maxStrLen];
    challenge_powers[0] <== 1;
    challenge_powers[1] <== random_challenge;
    for (var i = 2; i < maxStrLen; i++) {
        challenge_powers[i] <== challenge_powers[i-1] * random_challenge;
    }

    signal selector_bits[maxStrLen] <== ArraySelector(maxStrLen)(start_index, start_index+substr_len, enabled);

    signal selected_str[maxStrLen];
    for (var i = 0; i < maxStrLen; i++) {
        selected_str[i] <== selector_bits[i] * str[i];
    }
    
    signal str_poly[maxStrLen];
    for (var i = 0; i < maxStrLen; i++) {
        str_poly[i] <== selected_str[i] * challenge_powers[i];
    }

    signal substr_poly[maxSubstrLen];
    for (var i = 0; i < maxSubstrLen; i++) {
        substr_poly[i] <== substr[i] * challenge_powers[i];
    }

    signal str_poly_eval <== CalculateTotal(maxStrLen)(str_poly);
    signal substr_poly_eval <== CalculateTotal(maxSubstrLen)(substr_poly);

    var distinguishing_value = SelectArrayValue(maxStrLen)(challenge_powers, start_index, enabled);

    // Fail if ArraySelector returns all 0s
    signal lhs_is_zero <== IsEqual()([str_poly_eval,0]);
    lhs_is_zero === 0;

    AssertEqualIfTrue()([str_poly_eval,distinguishing_value * substr_poly_eval], enabled);
}

// Checks that `substr` of length `substr_len` matches `str` beginning at `start_index`
// Assumes `random_challenge` is computed by the Fiat-Shamir transform
// Takes in hash of the full string as an optimization, to prevent it being hashed 
// multiple times if the template is invoked on that string more than once
// Similar to `CheckSubstrInclusionPoly`
// Returns '1' if the check passes, '0' otherwise
// Assumes that:
// - `str_hash` is the hash of `str`
// - `substr` is 0-padded after `substr_len` characters
template CheckSubstrInclusionPolyBoolean(maxStrLen, maxSubstrLen) {
    signal input str[maxStrLen];
    signal input str_hash;
    signal input substr[maxSubstrLen];
    signal input substr_len;
    signal input start_index;
    signal input enabled;
    signal output success;

    signal substr_hash <== HashBytesToFieldWithLen(maxSubstrLen)(substr, substr_len);
    signal random_challenge <== Poseidon(4)([str_hash, substr_hash, substr_len, start_index]);

    signal challenge_powers[maxStrLen];
    challenge_powers[0] <== 1;
    challenge_powers[1] <== random_challenge;
    for (var i = 2; i < maxStrLen; i++) {
        challenge_powers[i] <== challenge_powers[i-1] * random_challenge;
    }
    signal selector_bits[maxStrLen] <== ArraySelector(maxStrLen)(start_index, start_index+substr_len, enabled);

    signal selected_str[maxStrLen];
    for (var i = 0; i < maxStrLen; i++) {
        selected_str[i] <== selector_bits[i] * str[i];
    }
    
    signal str_poly[maxStrLen];
    for (var i = 0; i < maxStrLen; i++) {
        str_poly[i] <== selected_str[i] * challenge_powers[i];
    }

    signal substr_poly[maxSubstrLen];
    for (var i = 0; i < maxSubstrLen; i++) {
        substr_poly[i] <== substr[i] * challenge_powers[i];
    }

    signal str_poly_eval <== CalculateTotal(maxStrLen)(str_poly);
    signal substr_poly_eval <== CalculateTotal(maxSubstrLen)(substr_poly);

    var distinguishing_value = SelectArrayValue(maxStrLen)(challenge_powers, start_index, enabled);

    // Fail if ArraySelector returns all 0s
    signal lhs_is_zero <== IsEqual()([str_poly_eval,0]);
    signal not_lhs_is_zero <== NOT()(lhs_is_zero);

    signal right_eq <== distinguishing_value * substr_poly_eval;
    signal check_passes <== IsEqual()([str_poly_eval, right_eq]);
    success <== AND()(not_lhs_is_zero, check_passes);
}

// Given `full_string`, `left`, and `right`, checks that full_string = left || right 
// `random_challenge` is expected to be computed by the Fiat-Shamir transform
// Assumes `right_len` has been validated to be correct outside of this subcircuit, i.e. that
// `right` is 0-padded after `right_len` values
// Enforces:
// - that `left` is 0-padded after `left_len` values
// - full_string = left || right where || is concatenation
template ConcatenationCheck(maxFullStringLen, maxLeftStringLen, maxRightStringLen) {
    signal input full_string[maxFullStringLen];
    signal input left[maxLeftStringLen];
    signal input right[maxRightStringLen];
    signal input left_len;
    signal input right_len;
    signal input enabled;
    
    signal left_hash <== HashBytesToFieldWithLen(maxLeftStringLen)(left, left_len); 
    signal right_hash <== HashBytesToFieldWithLen(maxRightStringLen)(right, right_len);
    signal full_hash <== HashBytesToFieldWithLen(maxFullStringLen)(full_string, left_len+right_len);
    signal random_challenge <== Poseidon(4)([left_hash, right_hash, full_hash, left_len]);

    // Enforce that all values to the right of `left_len` in `left` are 0-padding. Otherwise an attacker could place the leftmost part of `right` at the end of `left` and still have the polynomial check pass
    signal left_selector[maxLeftStringLen] <== RightArraySelector(maxLeftStringLen)(left_len-1, enabled);
    for (var i = 0; i < maxLeftStringLen; i++) {
        left_selector[i] * left[i] === 0;
    }
        

    signal challenge_powers[maxFullStringLen];
    challenge_powers[0] <== 1;
    challenge_powers[1] <== random_challenge;
    for (var i = 2; i < maxFullStringLen; i++) {
       challenge_powers[i] <== challenge_powers[i-1] * random_challenge; 
    }
    
    signal left_poly[maxLeftStringLen];
    for (var i = 0; i < maxLeftStringLen; i++) {
       left_poly[i] <== left[i] * challenge_powers[i];
    }

    signal right_poly[maxRightStringLen];
    for (var i = 0; i < maxRightStringLen; i++) {
        right_poly[i] <== right[i] * challenge_powers[i];
    }

    signal full_poly[maxFullStringLen];
    for (var i = 0; i < maxFullStringLen; i++) {
        full_poly[i] <== full_string[i] * challenge_powers[i];
    }

    signal left_poly_eval <== CalculateTotal(maxLeftStringLen)(left_poly);
    signal right_poly_eval <== CalculateTotal(maxRightStringLen)(right_poly);
    signal full_poly_eval <== CalculateTotal(maxFullStringLen)(full_poly);

    var distinguishing_value = SelectArrayValue(maxFullStringLen)(challenge_powers, left_len, enabled);

    full_poly_eval === left_poly_eval + distinguishing_value * right_poly_eval;
}

// Enforces that every value in `in` between 0 and len-1 are valid ASCII digits, i.e. are between
// 48 and 57 inclusive
template CheckAreASCIIDigits(maxNumDigits) {
    signal input in[maxNumDigits];
    signal input len;
    signal input enabled;

    signal selector[maxNumDigits] <== ArraySelector(maxNumDigits)(0, len, enabled);
    for (var i = 0; i < maxNumDigits; i++) {
        var is_less_than_max = LessThan(9)([in[i], 58]);
        var is_greater_than_min = GreaterThan(9)([in[i], 47]);
        var is_ascii_digit = AND()(is_less_than_max, is_greater_than_min);
        (1-is_ascii_digit) * selector[i] === 0;
    }
}

// Given a string of digits in ASCII format, returns the digits represented as a single field element
// Assumes:
// - the number represented by the ASCII `digits` is smaller than the scalar field used by the circuit
// - `digits` contains only ASCII digit values between 48 and 57 inclusive
// Does not work when maxLen = 1
template ASCIIDigitsToField(maxLen) {
    signal input digits[maxLen]; 
    signal input len; 
    signal input enabled;
    signal output out;

    CheckAreASCIIDigits(maxLen)(digits, len, enabled);
    // Set to 0 everywhere except len-1, which is 1
    signal index_eq[maxLen - 1];

    // For ASCII digits ['1','2','3','4','5'], acc_shifts[0..3] is [12,123,1234]
    signal acc_shifts[maxLen - 1];
    // accumulators[i] = acc_shifts[i-1] for all i < len, otherwise accumulators[i] = accumulators[i-1]
    signal accumulators[maxLen];

    signal success;
    var index_eq_sum = 0;
    // `s` is initally set to 1 and is 0 after len == i
    var s = 1; 

    accumulators[0] <== digits[0]-48;
    for (var i=1; i<maxLen; i++) {
        index_eq[i-1] <-- (len == i) ? 1 : 0;
        index_eq[i-1] * (len-i) === 0;

        s = s - index_eq[i-1];
        index_eq_sum = index_eq_sum + index_eq[i-1];

        acc_shifts[i-1] <== 10 * accumulators[i-1] + (digits[i]-48);
        // // This implements a conditional assignment: accumulators[i] = (s == 0 ? accumulators[i-1] : acc_shifts[i-1]);
        accumulators[i] <== (acc_shifts[i-1] - accumulators[i-1])*s + accumulators[i-1];
    }

    index_eq_sum ==> success;
    // Guarantee at most one element of index_eq is equal to 1
    success === 1;

    out <== accumulators[maxLen - 1];
}