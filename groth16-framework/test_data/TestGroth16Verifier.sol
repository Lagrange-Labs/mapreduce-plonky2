// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Groth16 verifier template.
/// @author Remco Bloemen
/// @notice Supports verifying Groth16 proofs. Proofs can be in uncompressed
/// (256 bytes) and compressed (128 bytes) format. A view function is provided
/// to compress proofs.
/// @notice See <https://2π.com/23/bn254-compression> for further explanation.
contract Verifier {
    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Base field Fp order P and scalar field Fr order R.
    // For BN254 these are computed as follows:
    //     t = 4965661367192848881
    //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant P =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Extension field Fp2 = Fp[i] / (i² + 1)
    // Note: This is the complex extension field of Fp with i² = -1.
    //       Values in Fp2 are represented as a pair of Fp elements (a₀, a₁) as a₀ + a₁⋅i.
    // Note: The order of Fp2 elements is *opposite* that of the pairing contract, which
    //       expects Fp2 elements in order (a₁, a₀). This is also the order in which
    //       Fp2 elements are encoded in the public interface as this became convention.

    // Constants in Fp
    uint256 constant FRACTION_1_2_FP =
        0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4;
    uint256 constant FRACTION_27_82_FP =
        0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 constant FRACTION_3_82_FP =
        0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FP =
        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45; // P - 2
    uint256 constant EXP_SQRT_FP =
        0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52; // (P + 1) / 4;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X =
        9546294761966233765293384560330710544459265382353062338342861498940409829308;
    uint256 constant ALPHA_Y =
        6351669133693229216911358925748869260064479371597314995229974645184308250505;

    // Groth16 beta point in G2 in powers of i
    uint256 constant BETA_NEG_X_0 =
        11724005098281667443232501382701253711437306636653463196335919602250785347547;
    uint256 constant BETA_NEG_X_1 =
        17727871460296049920160492313722573763783174634536985406878802022228351170547;
    uint256 constant BETA_NEG_Y_0 =
        20202059160607634354147493839396511542944699434614879632307317518393214874048;
    uint256 constant BETA_NEG_Y_1 =
        8835434270689616112472850414927345684501201981950730073674301923407554031354;

    // Groth16 gamma point in G2 in powers of i
    uint256 constant GAMMA_NEG_X_0 =
        16752557280390569762527910115516201693899885433532544054833515692285116807641;
    uint256 constant GAMMA_NEG_X_1 =
        7246019110534609685873747791657500403850817756790552416365041800316036665883;
    uint256 constant GAMMA_NEG_Y_0 =
        8921854670031665798840016861097621964201698369798743066907952565981939267075;
    uint256 constant GAMMA_NEG_Y_1 =
        20014136531582781224517453526026723230516102910356249587023960785544158267983;

    // Groth16 delta point in G2 in powers of i
    uint256 constant DELTA_NEG_X_0 =
        20657988654721339145588113091897563991659786769997059265781503549451176217615;
    uint256 constant DELTA_NEG_X_1 =
        21421142263922919318205802242039411891516837115974980522502315424176806225268;
    uint256 constant DELTA_NEG_Y_0 =
        1343467117933048968879183315971106219674437949939694932525280216734573247516;
    uint256 constant DELTA_NEG_Y_1 =
        13154839413817901383157824121417951886919026897609401578452809815244602845950;

    // Constant and public input points
    uint256 constant CONSTANT_X =
        4184707520520122011793257904234991669636509277996356990733518938236154882348;
    uint256 constant CONSTANT_Y =
        2928772078490041155860083958873861373866029315050845801841553420110722957080;
    uint256 constant PUB_0_X =
        9646450843619374243739412061822460067822064205203180136489041505279299542605;
    uint256 constant PUB_0_Y =
        19358245788298237649258444490581466630554587737745601877113118231618057494806;
    uint256 constant PUB_1_X =
        6175329032515415423113064451342742976830146775559375128244403739592158328744;
    uint256 constant PUB_1_Y =
        9120731556075515755649758816840983129664476344270715291706615465714907028825;
    uint256 constant PUB_2_X =
        5740909622769856994395125932379684298161590633551870858880733385028125505621;
    uint256 constant PUB_2_Y =
        7277627956714195653724015201540013321240007268732788243406148146081025382336;

    /// Negation in Fp.
    /// @notice Returns a number x such that a + x = 0 in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @return x the result
    function negate(uint256 a) internal pure returns (uint256 x) {
        unchecked {
            x = (P - (a % P)) % P; // Modulo is cheaper than branching
        }
    }

    /// Exponentiation in Fp.
    /// @notice Returns a number x such that a ^ e = x in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @param e the exponent
    /// @return x the result
    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            // Exponentiation failed.
            // Should not happen.
            revert ProofInvalid();
        }
    }

    /// Invertsion in Fp.
    /// @notice Returns a number x such that a * x = 1 in Fp.
    /// @notice The input does not need to be reduced.
    /// @notice Reverts with ProofInvalid() if the inverse does not exist
    /// @param a the input
    /// @return x the solution
    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        if (mulmod(a, x, P) != 1) {
            // Inverse does not exist.
            // Can only happen during G2 point decompression.
            revert ProofInvalid();
        }
    }

    /// Square root in Fp.
    /// @notice Returns a number x such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function sqrt_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        if (mulmod(x, x, P) != a) {
            // Square root does not exist or a is not reduced.
            // Happens when G1 point is not on curve.
            revert ProofInvalid();
        }
    }

    /// Square test in Fp.
    /// @notice Returns wheter a number x exists such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function isSquare_Fp(uint256 a) internal view returns (bool) {
        uint256 x = exp(a, EXP_SQRT_FP);
        return mulmod(x, x, P) == a;
    }

    /// Square root in Fp2.
    /// @notice Fp2 is the complex extension Fp[i]/(i^2 + 1). The input is
    /// a0 + a1 ⋅ i and the result is x0 + x1 ⋅ i.
    /// @notice Will revert with InvalidProof() if
    ///   * the input is not a square,
    ///   * the hint is incorrect, or
    ///   * the input coefficents are not reduced.
    /// @param a0 The real part of the input.
    /// @param a1 The imaginary part of the input.
    /// @param hint A hint which of two possible signs to pick in the equation.
    /// @return x0 The real part of the square root.
    /// @return x1 The imaginary part of the square root.
    function sqrt_Fp2(
        uint256 a0,
        uint256 a1,
        bool hint
    ) internal view returns (uint256 x0, uint256 x1) {
        // If this square root reverts there is no solution in Fp2.
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        // If this square root reverts there is no solution in Fp2.
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);

        // Check result to make sure we found a root.
        // Note: this also fails if a0 or a1 is not reduced.
        if (
            a0 != addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P) ||
            a1 != mulmod(2, mulmod(x0, x1, P), P)
        ) {
            revert ProofInvalid();
        }
    }

    /// Compress a G1 point.
    /// @notice Reverts with InvalidProof if the coordinates are not reduced
    /// or if the point is not on the curve.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param x The X coordinate in Fp.
    /// @param y The Y coordinate in Fp.
    /// @return c The compresed point (x with one signal bit).
    function compress_g1(
        uint256 x,
        uint256 y
    ) internal view returns (uint256 c) {
        if (x >= P || y >= P) {
            // G1 point not in field.
            revert ProofInvalid();
        }
        if (x == 0 && y == 0) {
            // Point at infinity
            return 0;
        }

        // Note: sqrt_Fp reverts if there is no solution, i.e. the x coordinate is invalid.
        uint256 y_pos = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (y == y_pos) {
            return (x << 1) | 0;
        } else if (y == negate(y_pos)) {
            return (x << 1) | 1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G1 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param c The compresed point (x with one signal bit).
    /// @return x The X coordinate in Fp.
    /// @return y The Y coordinate in Fp.
    function decompress_g1(
        uint256 c
    ) internal view returns (uint256 x, uint256 y) {
        // Note that X = 0 is not on the curve since 0³ + 3 = 3 is not a square.
        // so we can use it to represent the point at infinity.
        if (c == 0) {
            // Point at infinity as encoded in EIP196 and EIP197.
            return (0, 0);
        }
        bool negate_point = c & 1 == 1;
        x = c >> 1;
        if (x >= P) {
            // G1 x coordinate not in field.
            revert ProofInvalid();
        }

        // Note: (x³ + 3) is irreducible in Fp, so it can not be zero and therefore
        //       y can not be zero.
        // Note: sqrt_Fp reverts if there is no solution, i.e. the point is not on the curve.
        y = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (negate_point) {
            y = negate(y);
        }
    }

    /// Compress a G2 point.
    /// @notice Reverts with InvalidProof if the coefficients are not reduced
    /// or if the point is not on the curve.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param x0 The real part of the X coordinate.
    /// @param x1 The imaginary poart of the X coordinate.
    /// @param y0 The real part of the Y coordinate.
    /// @param y1 The imaginary part of the Y coordinate.
    /// @return c0 The first half of the compresed point (x0 with two signal bits).
    /// @return c1 The second half of the compressed point (x1 unmodified).
    function compress_g2(
        uint256 x0,
        uint256 x1,
        uint256 y0,
        uint256 y1
    ) internal view returns (uint256 c0, uint256 c1) {
        if (x0 >= P || x1 >= P || y0 >= P || y1 >= P) {
            // G2 point not in field.
            revert ProofInvalid();
        }
        if ((x0 | x1 | y0 | y1) == 0) {
            // Point at infinity
            return (0, 0);
        }

        // Compute y^2
        // Note: shadowing variables and scoping to avoid stack-to-deep.
        uint256 y0_pos;
        uint256 y1_pos;
        {
            uint256 n3ab = mulmod(mulmod(x0, x1, P), P - 3, P);
            uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
            uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);
            y0_pos = addmod(
                FRACTION_27_82_FP,
                addmod(a_3, mulmod(n3ab, x1, P), P),
                P
            );
            y1_pos = negate(
                addmod(FRACTION_3_82_FP, addmod(b_3, mulmod(n3ab, x0, P), P), P)
            );
        }

        // Determine hint bit
        // If this sqrt fails the x coordinate is not on the curve.
        bool hint;
        {
            uint256 d = sqrt_Fp(
                addmod(mulmod(y0_pos, y0_pos, P), mulmod(y1_pos, y1_pos, P), P)
            );
            hint = !isSquare_Fp(
                mulmod(addmod(y0_pos, d, P), FRACTION_1_2_FP, P)
            );
        }

        // Recover y
        (y0_pos, y1_pos) = sqrt_Fp2(y0_pos, y1_pos, hint);
        if (y0 == y0_pos && y1 == y1_pos) {
            c0 = (x0 << 2) | (hint ? 2 : 0) | 0;
            c1 = x1;
        } else if (y0 == negate(y0_pos) && y1 == negate(y1_pos)) {
            c0 = (x0 << 2) | (hint ? 2 : 0) | 1;
            c1 = x1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G2 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param c0 The first half of the compresed point (x0 with two signal bits).
    /// @param c1 The second half of the compressed point (x1 unmodified).
    /// @return x0 The real part of the X coordinate.
    /// @return x1 The imaginary poart of the X coordinate.
    /// @return y0 The real part of the Y coordinate.
    /// @return y1 The imaginary part of the Y coordinate.
    function decompress_g2(
        uint256 c0,
        uint256 c1
    ) internal view returns (uint256 x0, uint256 x1, uint256 y0, uint256 y1) {
        // Note that X = (0, 0) is not on the curve since 0³ + 3/(9 + i) is not a square.
        // so we can use it to represent the point at infinity.
        if (c0 == 0 && c1 == 0) {
            // Point at infinity as encoded in EIP197.
            return (0, 0, 0, 0);
        }
        bool negate_point = c0 & 1 == 1;
        bool hint = c0 & 2 == 2;
        x0 = c0 >> 2;
        x1 = c1;
        if (x0 >= P || x1 >= P) {
            // G2 x0 or x1 coefficient not in field.
            revert ProofInvalid();
        }

        uint256 n3ab = mulmod(mulmod(x0, x1, P), P - 3, P);
        uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);

        y0 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        y1 = negate(
            addmod(FRACTION_3_82_FP, addmod(b_3, mulmod(n3ab, x0, P), P), P)
        );

        // Note: sqrt_Fp2 reverts if there is no solution, i.e. the point is not on the curve.
        // Note: (X³ + 3/(9 + i)) is irreducible in Fp2, so y can not be zero.
        //       But y0 or y1 may still independently be zero.
        (y0, y1) = sqrt_Fp2(y0, y1, hint);
        if (negate_point) {
            y0 = negate(y0);
            y1 = negate(y1);
        }
    }

    /// Compute the public input linear combination.
    /// @notice Reverts with PublicInputNotInField if the input is not in the field.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @return x The X coordinate of the resulting G1 point.
    /// @return y The Y coordinate of the resulting G1 point.
    function publicInputMSM(
        uint256[3] calldata input
    ) internal view returns (uint256 x, uint256 y) {
        // Note: The ECMUL precompile does not reject unreduced values, so we check this.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        // ECMUL has input (x, y, scalar) and output (x', y').
        // ECADD has input (x1, y1, x2, y2) and output (x', y').
        // We call them such that ecmul output is already in the second point
        // argument to ECADD so we can have a tight loop.
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, CONSTANT_X)
            mstore(add(f, 0x20), CONSTANT_Y)
            mstore(g, PUB_0_X)
            mstore(add(g, 0x20), PUB_0_Y)
            s := calldataload(input)
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_1_X)
            mstore(add(g, 0x20), PUB_1_Y)
            s := calldataload(add(input, 32))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_2_X)
            mstore(add(g, 0x20), PUB_2_Y)
            s := calldataload(add(input, 64))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Compress a proof.
    /// @notice Will revert with InvalidProof if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof The uncompressed Groth16 proof. Elements are in the same order as for
    /// verifyProof. I.e. Groth16 points (A, B, C) encoded as in EIP-197.
    /// @return compressed The compressed proof. Elements are in the same order as for
    /// verifyCompressedProof. I.e. points (A, B, C) in compressed format.
    function compressProof(
        uint256[8] calldata proof
    ) public view returns (uint256[4] memory compressed) {
        compressed[0] = compress_g1(proof[0], proof[1]);
        (compressed[2], compressed[1]) = compress_g2(
            proof[3],
            proof[2],
            proof[5],
            proof[4]
        );
        compressed[3] = compress_g1(proof[6], proof[7]);
    }

    /// Verify a Groth16 proof with compressed points.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param compressedProof the points (A, B, C) in compressed format
    /// matching the output of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[3] calldata input
    ) public view {
        (uint256 Ax, uint256 Ay) = decompress_g1(compressedProof[0]);
        (uint256 Bx0, uint256 Bx1, uint256 By0, uint256 By1) = decompress_g2(
            compressedProof[2],
            compressedProof[1]
        );
        (uint256 Cx, uint256 Cy) = decompress_g1(compressedProof[3]);
        (uint256 Lx, uint256 Ly) = publicInputMSM(input);

        // Verify the pairing
        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        uint256[24] memory pairings;
        // e(A, B)
        pairings[0] = Ax;
        pairings[1] = Ay;
        pairings[2] = Bx1;
        pairings[3] = Bx0;
        pairings[4] = By1;
        pairings[5] = By0;
        // e(C, -δ)
        pairings[6] = Cx;
        pairings[7] = Cy;
        pairings[8] = DELTA_NEG_X_1;
        pairings[9] = DELTA_NEG_X_0;
        pairings[10] = DELTA_NEG_Y_1;
        pairings[11] = DELTA_NEG_Y_0;
        // e(α, -β)
        pairings[12] = ALPHA_X;
        pairings[13] = ALPHA_Y;
        pairings[14] = BETA_NEG_X_1;
        pairings[15] = BETA_NEG_X_0;
        pairings[16] = BETA_NEG_Y_1;
        pairings[17] = BETA_NEG_Y_0;
        // e(L_pub, -γ)
        pairings[18] = Lx;
        pairings[19] = Ly;
        pairings[20] = GAMMA_NEG_X_1;
        pairings[21] = GAMMA_NEG_X_0;
        pairings[22] = GAMMA_NEG_Y_1;
        pairings[23] = GAMMA_NEG_Y_0;

        // Check pairing equation.
        bool success;
        uint256[1] memory output;
        assembly ("memory-safe") {
            success := staticcall(
                gas(),
                PRECOMPILE_VERIFY,
                pairings,
                0x300,
                output,
                0x20
            )
        }
        if (!success || output[0] != 1) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the points (A, B, C) in EIP-197 format matching the output
    /// of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[3] calldata input
    ) public view {
        (uint256 x, uint256 y) = publicInputMSM(input);

        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.

        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40) // Free memory pointer.

            // Copy points (A, B, C) to memory. They are already in correct encoding.
            // This is pairing e(A, B) and G1 of e(C, -δ).
            calldatacopy(f, proof, 0x100)

            // Complete e(C, -δ) and write e(α, -β), e(L_pub, -γ) to memory.
            // OPT: This could be better done using a single codecopy, but
            //      Solidity (unlike standalone Yul) doesn't provide a way to
            //      to do this.
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)
            mstore(add(f, 0x240), x)
            mstore(add(f, 0x260), y)
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            // Check pairing equation.
            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20)
            // Also check returned value (both are either 1 or 0).
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }

    bytes32 constant CIRCUIT_DIGEST =
        0x231eaa7fb7509d5345f2997ebaaed9bbef01f2bc6e70952dc0af493c3df7a0aa;

    // Top 3 bits mask.
    uint256 constant TOP_THREE_BIT_MASK = ~(uint256(7) << 253);

    // Generic constants for the supported queries
    // TODO: These constants are possible to be changed depending on user queries exploration.
    // Once we know which queries users are mostly doing, we'll be able to modify these constants.
    // Maximum number of the results
    uint32 constant MAX_NUM_OUTPUTS = 3;
    // Maximum number of the items per result
    uint32 constant MAX_NUM_ITEMS_PER_OUTPUT = 5;
    // Maximum number of the placeholders
    uint32 constant MAX_NUM_PLACEHOLDERS = 14;

    // The start uint256 offset of the public inputs in calldata.
    // groth16_proof_number (8) + groth16_input_number (3)
    uint32 constant PI_OFFSET = 11;

    // These values are aligned and each is an uint256.
    // Block hash uint256 position in the public inputs
    uint32 constant BLOCK_HASH_POS = 0;
    // Flattened computational hash uint256 position
    uint32 constant COMPUTATIONAL_HASH_POS = BLOCK_HASH_POS + 1;
    // Placeholder values uint256 position
    uint32 constant PLACEHOLDER_VALUES_POS = COMPUTATIONAL_HASH_POS + 1;
    // Result values uint256 position
    uint32 constant RESULT_VALUES_POS =
        PLACEHOLDER_VALUES_POS + MAX_NUM_PLACEHOLDERS;

    // The remaining items of public inputs are saved in one uint256.
    // The uint256 offset of the last uint256 of public inputs in calldata.
    uint32 constant PI_REM_OFFSET =
        PI_OFFSET +
            RESULT_VALUES_POS +
            MAX_NUM_OUTPUTS *
            MAX_NUM_ITEMS_PER_OUTPUT;
    // Placeholder number uint32 position in the last uint256
    uint32 constant REM_NUM_PLACEHOLDERS_POS = 0;
    // Result number uint32 position
    uint32 constant REM_NUM_RESULTS_POS = 1;
    // Entry count (current result number) uint32 position
    uint32 constant REM_ENTRY_COUNT_POS = 2;
    // Overflow flag uint32 position
    uint32 constant REM_OVERFLOW_POS = 3;
    // Query limit uint32 position
    uint32 constant REM_QUERY_LIMIT_POS = 4;
    // Query offset uint32 position
    uint32 constant REM_QUERY_OFFSET_POS = 5;

    // The total byte length of public inputs
    uint32 constant PI_LEN =
        32 * (PI_REM_OFFSET - PI_OFFSET) + (REM_QUERY_OFFSET_POS + 1) * 4;

    // A computation overflow error during the query process
    error QueryComputationOverflow();

    // The query input struct passed into the processQuery function
    struct QueryInput {
        // Query limit parameter
        uint32 limit;
        // Query offset parameter
        uint32 offset;
        // Minimum block number
        uint64 minBlockNumber;
        // Maximum block number
        uint64 maxBlockNumber;
        // Block hash
        bytes32 blockHash;
        // Computational hash
        bytes32 computationalHash;
        // User placeholder values
        uint256[] userPlaceholders;
    }

    // The query output struct returned from the processQuery function
    struct QueryOutput {
        // Total number of the all matching rows
        uint256 totalMatchedRows;
        // Returned rows of the current cursor
        bytes[] rows;
    }

    // The processQuery function does the followings:
    // 1. Parse the Groth16 proofs (8 uint256) and inputs (3 uint256) from the `data`
    //    argument, and call `verifyProof` function for Groth16 verification.
    // 2. Calculate sha256 on the public inputs, and set the top 3 bits of this hash to 0.
    //    Then ensure this hash value equals to the last Groth16 input (groth16_inputs[2]).
    // 3. Parse the items from public inputs, and check as expected for query.
    // 4. Parse and return the query output from public inputs.
    function processQuery(
        bytes32[] calldata data,
        QueryInput memory query
    ) public view returns (QueryOutput memory) {
        // 1. Groth16 verification
        uint256[3] memory groth16Inputs = verifyGroth16Proof(data);

        // 2. Ensure the sha256 of public inputs equals to the last Groth16 input.
        verifyPublicInputs(data, groth16Inputs);

        // 3. Ensure the items of public inputs equal as expected for query.
        verifyQuery(data, query);

        // 4. Parse and return the query output.
        return parseOutput(data);
    }

    // Parse the Groth16 proofs and inputs, do verification, and returns the Groth16 inputs.
    function verifyGroth16Proof(
        bytes32[] calldata data
    ) internal view returns (uint256[3] memory) {
        uint256[8] memory proofs;
        uint256[3] memory inputs;

        for (uint32 i = 0; i < 8; ++i) {
            proofs[i] = uint256(data[i]);
        }
        for (uint32 i = 0; i < 3; ++i) {
            inputs[i] = uint256(data[i + 8]);
        }

        // Ensure the sha256 hash equals to the last Groth16 input.
        require(
            inputs[0] == uint256(CIRCUIT_DIGEST),
            "The first Groth16 input must be equal to the circuit digest"
        );

        // Verify the Groth16 proof.
        this.verifyProof(proofs, inputs);

        return inputs;
    }

    // Compute sha256 on the public inputs, and ensure it equals to the last Groth16 input.
    function verifyPublicInputs(
        bytes32[] calldata data,
        uint256[3] memory groth16Inputs
    ) internal pure {
        // Parse the public inputs from calldata.
        bytes memory pi = parsePublicInputs(data);

        // Calculate sha256.
        uint256 hash = uint256(sha256(pi));
        // Set the top 3 bits of the hash value to 0.
        hash = hash & TOP_THREE_BIT_MASK;

        // Require the sha256 equals to the last Groth16 input.
        require(
            hash == groth16Inputs[2],
            "The sha256 hash of public inputs must be equal to the last of the Groth16 inputs"
        );
    }

    // Parse the public inputs from calldata.
    function parsePublicInputs(
        bytes32[] calldata data
    ) internal pure returns (bytes memory) {
        bytes memory pi = new bytes(PI_LEN);

        // The calldata is encoded as Bytes32.
        uint256 b32Len = PI_LEN / 32;
        for (uint256 i = 0; i < b32Len; ++i) {
            bytes32 b = data[PI_OFFSET + i];
            for (uint32 j = 0; j < 32; ++j) {
                pi[i * 32 + j] = bytes1(b[j]);
            }
        }
        bytes32 rem = data[PI_OFFSET + b32Len];
        for (uint32 i = 0; i < PI_LEN % 32; ++i) {
            pi[b32Len * 32 + i] = rem[i];
        }

        return pi;
    }

    // Verify the public inputs with the expected query.
    function verifyQuery(
        bytes32[] calldata data,
        QueryInput memory query
    ) internal pure {
        // Retrieve the last Uint256 of public inputs.
        bytes32 rem = data[PI_REM_OFFSET];

        // Check the block hash and computational hash.
        bytes32 blockHash = data[PI_OFFSET + BLOCK_HASH_POS];
        require(
            blockHash == query.blockHash,
            "Block hash must equal as expected."
        );
        bytes32 computationalHash = data[PI_OFFSET + COMPUTATIONAL_HASH_POS];
        require(
            computationalHash == query.computationalHash,
            "Computational hash must equal as expected."
        );

        uint32 numPlaceholders = uint32(
            bytes4(rem << (REM_NUM_PLACEHOLDERS_POS * 32))
        );
        require(
            numPlaceholders <= MAX_NUM_PLACEHOLDERS,
            "Placeholder number cannot overflow."
        );
        require(
            // The first two placeholders are minimum and maximum block numbers.
            numPlaceholders == query.userPlaceholders.length + 2,
            "Placeholder number cannot overflow and must equal as expected."
        );
        // Check the minimum and maximum block numbers.
        require(
            uint256(data[PI_OFFSET + PLACEHOLDER_VALUES_POS]) ==
                query.minBlockNumber,
            "The first placeholder must be the expected minimum block number."
        );
        require(
            uint256(data[PI_OFFSET + PLACEHOLDER_VALUES_POS + 1]) ==
                query.maxBlockNumber,
            "The second placeholder must be the expected maximum block number."
        );
        // Check the user placeholders.
        for (uint256 i = 0; i < numPlaceholders - 2; ++i) {
            require(
                uint256(data[PI_OFFSET + PLACEHOLDER_VALUES_POS + 2 + i]) ==
                    query.userPlaceholders[i],
                "The user placeholder must equal as expected."
            );
        }

        // Check the query limit and offset.
        uint32 limit = uint32(bytes4(rem << (REM_QUERY_LIMIT_POS * 32)));
        require(limit == query.limit, "Query limit must equal as expected.");
        uint32 offset = uint32(bytes4(rem << (REM_QUERY_OFFSET_POS * 32)));
        require(offset == query.offset, "Query limit must equal as expected.");

        // Throw an error if overflow.
        uint32 overflow = uint32(bytes4(rem << (REM_OVERFLOW_POS * 32)));
        if (overflow != 0) {
            revert QueryComputationOverflow();
        }
    }

    // Parse the query output from the public inputs.
    function parseOutput(
        bytes32[] calldata data
    ) internal pure returns (QueryOutput memory) {
        bytes32 rem = data[PI_REM_OFFSET];

        // Retrieve total number of the matched rows.
        uint32 totalMatchedRows = uint32(
            bytes4(rem << (REM_ENTRY_COUNT_POS * 32))
        );

        // Retrieve the current result number.
        uint32 numResults = uint32(bytes4(rem << (REM_NUM_RESULTS_POS * 32)));
        require(
            numResults <= MAX_NUM_OUTPUTS,
            "Result number cannot overflow."
        );

        // TODO: Each result value is an Uint256 and need to confirm this encoding code.
        // And it encodes the whole row with dummy values, since we don't know the real
        // number of items per result here.
        uint32 offset = PI_OFFSET + RESULT_VALUES_POS;
        bytes[] memory rows = new bytes[](numResults);
        for (uint256 i = 0; i < numResults; ++i) {
            rows[i] = abi.encode(
                data[offset + i * MAX_NUM_ITEMS_PER_OUTPUT:offset +
                    (i + 1) *
                    MAX_NUM_ITEMS_PER_OUTPUT]
            );
        }

        QueryOutput memory output = QueryOutput({
            totalMatchedRows: totalMatchedRows,
            rows: rows
        });

        return output;
    }
}
