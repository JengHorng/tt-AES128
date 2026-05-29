`timescale 1ns/1ps
// =============================================================================
// aes_top.v  —  AES-128 with ONE shared S-box (Tiny Tapeout, minimum area)
// =============================================================================
// ONE aes_sbox_rom instance for BOTH data SubBytes AND key expansion SubWord.
// Area: ~800 (S-box) + ~500 (MixCols) + ~400 (other) ≈ 1,700 cells
//
// Encryption timing (221 cycles total):
//   Cycle 0        : initial AddRoundKey  (S_READY)
//   Per round (×10): 20 cycles SubBytes+SubWord + 1 done + 1 S_ROUND = 22 cycles
//   Total          : 1 + 10×22 = 221 cycles to valid_out
//
// Shared S-box schedule per round:
//   sub_cnt  1-16 : S-box on 16 data bytes  → sub_accum (SubBytes result)
//   sub_cnt 17-20 : S-box on 4 RotWord bytes → kx_accum  (SubWord result)
//   sub_cnt 21    : done pulse, rk advanced to next round key
// =============================================================================

module aes_top (
    input  wire         clk,
    input  wire         rst_n,

    input  wire [127:0] key_in,
    input  wire         key_load,
    output reg          key_ready,

    input  wire [127:0] plaintext_in,
    input  wire         valid_in,
    output wire         ready_in,

    output reg  [127:0] ciphertext_out,
    output reg          valid_out,
    input  wire         ready_out
);

    // ── FSM states ───────────────────────────────────────────────────────────
    localparam S_IDLE  = 2'd0;
    localparam S_READY = 2'd1;
    localparam S_SUB   = 2'd2;   // SubBytes (cnt 1-16) + SubWord (cnt 17-20)
    localparam S_ROUND = 2'd3;   // ShiftRows + MixCols/ARK

    reg [1:0]   state;
    reg [3:0]   enc_ctr;     // round counter 1..10

    // ── AES registers ────────────────────────────────────────────────────────
    reg [127:0] aes_state;
    reg [127:0] rk;
    reg [127:0] orig_key;

    // ── Single shared S-box ──────────────────────────────────────────────────
    reg  [4:0]   sub_cnt;      // 0=idle, 1-16=data, 17-20=key, 21=done

    reg  [127:0] sub_shift;    // 128-bit shift reg: cycles through state bytes
    reg  [127:0] sub_accum;    // accumulates SubBytes result (16 bytes)

    reg  [31:0]  kx_shift;     // 32-bit shift reg: cycles through RotWord bytes
    reg  [31:0]  kx_accum;     // accumulates SubWord result (4 bytes)

    // S-box input MUX: data bytes (cnt 1-16) or key bytes (cnt 17-20)
    wire [7:0]  sbox_in  = (sub_cnt <= 5'd16) ? sub_shift[127:120]
                                               : kx_shift[31:24];
    wire [7:0]  sbox_out;
    aes_sbox_rom sbox (.addr(sbox_in), .data(sbox_out));

    wire sub_done = (sub_cnt == 5'd21);

    // ── Next round key (combinational, uses kx_accum after SubWord) ──────────
    // Called in done cycle: enc_ctr already holds the current round number
    wire [31:0] kx_rcon = get_rcon(enc_ctr);
    wire [31:0] kx_nw4  = rk[127:96] ^ kx_accum ^ kx_rcon;
    wire [31:0] kx_nw5  = rk[95:64]  ^ kx_nw4;
    wire [31:0] kx_nw6  = rk[63:32]  ^ kx_nw5;
    wire [31:0] kx_nw7  = rk[31:0]   ^ kx_nw6;
    wire [127:0] next_rk = {kx_nw4, kx_nw5, kx_nw6, kx_nw7};

    function [31:0] get_rcon;
        input [3:0] r;
        begin
            case (r)
                4'd1:  get_rcon = 32'h01000000;
                4'd2:  get_rcon = 32'h02000000;
                4'd3:  get_rcon = 32'h04000000;
                4'd4:  get_rcon = 32'h08000000;
                4'd5:  get_rcon = 32'h10000000;
                4'd6:  get_rcon = 32'h20000000;
                4'd7:  get_rcon = 32'h40000000;
                4'd8:  get_rcon = 32'h80000000;
                4'd9:  get_rcon = 32'h1b000000;
                4'd10: get_rcon = 32'h36000000;
                default: get_rcon = 32'h00000000;
            endcase
        end
    endfunction

    // ── Combinational round transforms (applied in S_ROUND) ──────────────────
    wire [127:0] shift_out;
    wire [127:0] mix_out;
    ShiftRows  sr (.state_in(aes_state), .state_out(shift_out));
    MixColumns mc (.state_in(shift_out),  .state_out(mix_out));

    assign ready_in = (state == S_READY);

    // ── Main FSM (all in one always block — no cross-module NBA races) ────────
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_IDLE;
            key_ready     <= 1'b0;
            valid_out     <= 1'b0;
            enc_ctr       <= 4'd0;
            sub_cnt       <= 5'd0;
            aes_state     <= 128'h0;
            rk            <= 128'h0;
            orig_key      <= 128'h0;
            ciphertext_out<= 128'h0;
            sub_shift     <= 128'h0;
            sub_accum     <= 128'h0;
            kx_shift      <= 32'h0;
            kx_accum      <= 32'h0;
        end else begin
            valid_out <= 1'b0;

            // ── Shared S-box counter (runs autonomously) ─────────────────────
            if (sub_cnt >= 5'd1 && sub_cnt <= 5'd20) begin
                if (sub_cnt <= 5'd16) begin
                    // Data SubBytes phase: shift state, accumulate result
                    sub_shift <= {sub_shift[119:0], 8'h00};
                    sub_accum <= {sub_accum[119:0], sbox_out};
                end else begin
                    // Key SubWord phase: shift key bytes, accumulate
                    kx_shift  <= {kx_shift[23:0],  8'h00};
                    kx_accum  <= {kx_accum[23:0],  sbox_out};
                end
                sub_cnt <= sub_cnt + 5'd1;   // 1→2→...→20→21
            end else if (sub_cnt == 5'd21) begin
                sub_cnt <= 5'd0;             // done pulse → back to idle
            end
            // sub_cnt==0: idle, started by FSM below

            // ── FSM ──────────────────────────────────────────────────────────
            case (state)

                S_IDLE: begin
                    key_ready <= 1'b0;
                    if (key_load) begin
                        orig_key  <= key_in;
                        rk        <= key_in;
                        key_ready <= 1'b1;
                        enc_ctr   <= 4'd0;
                        state     <= S_READY;
                    end
                end

                S_READY: begin
                    key_ready <= 1'b1;
                    if (key_load) begin
                        orig_key <= key_in;
                        rk       <= key_in;
                        enc_ctr  <= 4'd0;
                    end else if (valid_in) begin
                        // Initial ARK, then start SubBytes+SubWord
                        sub_shift <= plaintext_in ^ rk;       // PT ^ RK0
                        sub_accum <= 128'h0;
                        kx_shift  <= {rk[23:0], rk[31:24]};   // RotWord(RK0[31:0])
                        kx_accum  <= 32'h0;
                        sub_cnt   <= 5'd1;
                        aes_state <= plaintext_in ^ rk;        // keep copy
                        enc_ctr   <= 4'd1;
                        state     <= S_SUB;
                    end
                end

                S_SUB: begin
                    if (sub_done) begin
                        // sub_accum = SubBytes(aes_state)
                        // kx_accum  = SubWord(RotWord(rk[31:0]))
                        // next_rk computed combinationally from kx_accum + rk
                        aes_state <= sub_accum;   // SubBytes result
                        rk        <= next_rk;     // advance round key
                        state     <= S_ROUND;
                    end
                end

                S_ROUND: begin
                    // aes_state = SubBytes result, rk = current round key
                    // shift_out = ShiftRows(aes_state)  [combinational]
                    // mix_out   = MixCols(shift_out)    [combinational]
                    if (enc_ctr <= 4'd9) begin
                        // Standard round: ARK, start next SubBytes+SubWord
                        sub_shift <= mix_out ^ rk;
                        sub_accum <= 128'h0;
                        kx_shift  <= {rk[23:0], rk[31:24]};  // RotWord(new rk[31:0])
                        kx_accum  <= 32'h0;
                        sub_cnt   <= 5'd1;
                        aes_state <= mix_out ^ rk;
                        enc_ctr   <= enc_ctr + 4'd1;
                        state     <= S_SUB;
                    end else begin
                        // Final round (enc_ctr=10): ShiftRows + ARK, no MixCols
                        ciphertext_out <= shift_out ^ rk;
                        valid_out      <= 1'b1;
                        rk             <= orig_key;
                        enc_ctr        <= 4'd0;
                        sub_cnt        <= 5'd0;
                        state          <= S_READY;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
