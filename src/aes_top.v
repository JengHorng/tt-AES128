`timescale 1ns/1ps

// =============================================================================
// aes_top.v  —  Iterative AES-128 Core  (Tiny Tapeout version)
// =============================================================================
//
// WHY ITERATIVE FOR TINY TAPEOUT:
//   Pipelined design : ~4,900 flip-flops  → OpenLane takes very long / fails
//   Iterative design :   ~400 flip-flops  → OpenLane completes quickly
//
// HOW IT WORKS:
//   One round of AES is computed per clock cycle using a SINGLE shared
//   combinational round function.  The same SubBytes, ShiftRows, MixColumns,
//   and AddRoundKey logic is reused for all 10 rounds.
//
//   Round keys are generated ON-THE-FLY — no pre-storage of all 11 round keys.
//   Only the original key (RK0) and the current round key are stored.
//
// TIMING:
//   Cycle 0  (in S_READY)  : initial AddRoundKey  — state = plaintext XOR RK0
//   Cycles 1–9 (S_ENCRYPT) : standard rounds 1–9  — SubBytes+ShiftRows+MixColumns+ARK
//   Cycle 10 (S_ENCRYPT)   : final round 10        — SubBytes+ShiftRows+ARK (no MixColumns)
//   Total : 11 cycles per encryption block
//
// INTERFACE: identical to the pipelined aes_top — no changes to tt_um_aes_project.v
//
// =============================================================================

module aes_top (
    input  wire         clk,
    input  wire         rst_n,

    // Key loading
    input  wire [127:0] key_in,
    input  wire         key_load,
    output reg          key_ready,

    // Streaming input
    input  wire [127:0] plaintext_in,
    input  wire         valid_in,
    output wire         ready_in,

    // Streaming output
    output reg  [127:0] ciphertext_out,
    output reg          valid_out,
    input  wire         ready_out
);

    // =========================================================================
    // FSM states
    // =========================================================================

    localparam S_IDLE    = 2'd0;  // waiting for first key_load
    localparam S_READY   = 2'd1;  // key loaded, ready to accept plaintext
    localparam S_ENCRYPT = 2'd2;  // running encryption rounds

    reg [1:0] state;

    // =========================================================================
    // Data registers  (~400 FFs total vs ~4900 in pipelined version)
    // =========================================================================

    reg [127:0] aes_state;   // 128 FFs — current AES state (changes each round)
    reg [127:0] rk;          // 128 FFs — current round key
    reg [127:0] orig_key;    // 128 FFs — original RK0 (used to reset rk between encryptions)
    reg [3:0]   enc_ctr;     //   4 FFs — round counter: 0 in S_READY, 1–10 in S_ENCRYPT

    // =========================================================================
    // Combinational round function (shared across all 10 rounds)
    //
    // Input  : aes_state register
    // Output : std_out  (rounds 1–9, includes MixColumns)
    //          final_out (round 10,  no MixColumns)
    // =========================================================================

    wire [127:0] sub_out;    // SubBytes output
    wire [127:0] shift_out;  // ShiftRows output
    wire [127:0] mix_out;    // MixColumns output

    subbytes       sub (.state_in(aes_state), .state_out(sub_out));
    ShiftRows       sr (.state_in(sub_out),   .state_out(shift_out));
    MixColumns_comb mc (.state_in(shift_out), .state_out(mix_out));

    wire [127:0] std_out   = mix_out   ^ rk;  // standard round result (rounds 1–9)
    wire [127:0] final_out = shift_out ^ rk;  // final   round result (round 10)

    // =========================================================================
    // On-the-fly key expansion (combinational, from current rk)
    //
    // next_rk = expand(rk, rcon[enc_ctr + 1])
    //
    // Timeline:
    //   S_READY  enc_ctr=0 : expand(RK0,  rcon[1])  = RK1
    //   S_ENCRYPT enc_ctr=1 : expand(RK1,  rcon[2])  = RK2
    //   ...
    //   S_ENCRYPT enc_ctr=9 : expand(RK9,  rcon[10]) = RK10
    //   (enc_ctr=10 : next_rk unused — we reset rk to orig_key instead)
    // =========================================================================

    wire [31:0] kx_w0 = rk[127:96];
    wire [31:0] kx_w1 = rk[95:64];
    wire [31:0] kx_w2 = rk[63:32];
    wire [31:0] kx_w3 = rk[31:0];

    wire [31:0] kx_rot  = {kx_w3[23:0], kx_w3[31:24]};  // RotWord
    wire [31:0] kx_sub;                                   // SubWord

    aes_sbox_rom ks0 (.addr(kx_rot[31:24]), .data(kx_sub[31:24]));
    aes_sbox_rom ks1 (.addr(kx_rot[23:16]), .data(kx_sub[23:16]));
    aes_sbox_rom ks2 (.addr(kx_rot[15:8]),  .data(kx_sub[15:8]));
    aes_sbox_rom ks3 (.addr(kx_rot[7:0]),   .data(kx_sub[7:0]));

    wire [31:0]  kx_rcon  = get_rcon(enc_ctr + 4'd1);
    wire [31:0]  kx_temp  = kx_sub ^ kx_rcon;
    wire [31:0]  kx_nw4   = kx_w0 ^ kx_temp;
    wire [31:0]  kx_nw5   = kx_w1 ^ kx_nw4;
    wire [31:0]  kx_nw6   = kx_w2 ^ kx_nw5;
    wire [31:0]  kx_nw7   = kx_w3 ^ kx_nw6;
    wire [127:0] next_rk  = {kx_nw4, kx_nw5, kx_nw6, kx_nw7};

    function [31:0] get_rcon;
        input [3:0] r;
        begin
            case (r)
                4'd1:    get_rcon = 32'h01000000;
                4'd2:    get_rcon = 32'h02000000;
                4'd3:    get_rcon = 32'h04000000;
                4'd4:    get_rcon = 32'h08000000;
                4'd5:    get_rcon = 32'h10000000;
                4'd6:    get_rcon = 32'h20000000;
                4'd7:    get_rcon = 32'h40000000;
                4'd8:    get_rcon = 32'h80000000;
                4'd9:    get_rcon = 32'h1b000000;
                4'd10:   get_rcon = 32'h36000000;
                default: get_rcon = 32'h00000000;
            endcase
        end
    endfunction

    // =========================================================================
    // ready_in — high whenever the core is in S_READY
    // =========================================================================

    assign ready_in = (state == S_READY);

    // =========================================================================
    // Main FSM
    // =========================================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_IDLE;
            key_ready     <= 1'b0;
            valid_out     <= 1'b0;
            enc_ctr       <= 4'd0;
        end else begin

            valid_out <= 1'b0;  // default: not valid (override below when done)

            case (state)

                // ─────────────────────────────────────────────────────────
                // S_IDLE — wait for the first key_load pulse
                // ─────────────────────────────────────────────────────────
                S_IDLE: begin
                    key_ready <= 1'b0;
                    if (key_load) begin
                        orig_key  <= key_in;   // store RK0
                        rk        <= key_in;   // seed the key expander
                        key_ready <= 1'b1;
                        enc_ctr   <= 4'd0;
                        state     <= S_READY;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // S_READY — key ready, waiting for plaintext
                //
                // On valid_in: perform initial AddRoundKey (round 0)
                //   state  = plaintext XOR RK0
                //   rk     = RK1  (pre-computed via next_rk)
                //   enc_ctr = 1   (round 1 will run next cycle)
                // ─────────────────────────────────────────────────────────
                S_READY: begin
                    key_ready <= 1'b1;

                    if (key_load) begin
                        // Hot key swap — load new key without full reset
                        orig_key <= key_in;
                        rk       <= key_in;
                        enc_ctr  <= 4'd0;
                    end else if (valid_in) begin
                        // Initial AddRoundKey (enc_ctr = 0, rk = RK0)
                        aes_state <= plaintext_in ^ rk;  // state = PT XOR RK0
                        rk        <= next_rk;             // rk = RK1
                        enc_ctr   <= 4'd1;
                        state     <= S_ENCRYPT;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // S_ENCRYPT — iterate through rounds 1 to 10
                //
                // enc_ctr 1–9  : standard rounds (SubBytes+ShiftRows+MixColumns+ARK)
                // enc_ctr 10   : final round     (SubBytes+ShiftRows+ARK, no MixColumns)
                //
                // Key is expanded one step per cycle alongside the round.
                // After round 10, rk is reset to orig_key ready for next block.
                // ─────────────────────────────────────────────────────────
                S_ENCRYPT: begin
                    if (enc_ctr <= 4'd9) begin
                        // Standard round: uses std_out = MixColumns(ShiftRows(SubBytes(aes_state))) XOR rk
                        aes_state <= std_out;
                        rk        <= next_rk;             // advance round key
                        enc_ctr   <= enc_ctr + 4'd1;
                    end else begin
                        // Final round (enc_ctr = 10):
                        // uses final_out = ShiftRows(SubBytes(aes_state)) XOR rk  (no MixColumns)
                        ciphertext_out <= final_out;
                        valid_out      <= 1'b1;
                        rk             <= orig_key;        // reset key for next block
                        enc_ctr        <= 4'd0;
                        state          <= S_READY;         // immediately ready for next block
                    end
                end

                default: state <= S_IDLE;

            endcase
        end
    end

endmodule
