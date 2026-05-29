`timescale 1ns/1ps
// =============================================================================
// aes_top.v  —  Iterative AES-128, SubBytes INLINED (Tiny Tapeout)
// =============================================================================
// SubBytes logic is inline (no sub-module), eliminating cross-module NBA races.
// One shared aes_sbox_rom for data SubBytes + 4 for key expansion = 5 total.
// Area: ~4,800 cells  (well within 4×2 tile budget of ~8,000 cells)
//
// Timing per encryption: 1 + 10×19 = 191 cycles
//   1  cycle  : initial AddRoundKey (S_READY)
//   17 cycles : SubBytes per round  (cnt 0→16 + done at 17)
//    1 cycle  : Round op            (ShiftRows+MixCols/ARK)
//   10 rounds × 19 = 190 + 1 = 191 total cycles to valid_out
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

    // ── FSM states ──────────────────────────────────────────────────────────
    localparam S_IDLE     = 2'd0;
    localparam S_READY    = 2'd1;
    localparam S_SUBBYTES = 2'd2;   // processing SubBytes (cnt 1..16)
    localparam S_ROUND    = 2'd3;   // ShiftRows + MixCols/ARK

    reg [1:0]   state;
    reg [3:0]   enc_ctr;    // round counter 1..10

    // ── AES state and key ────────────────────────────────────────────────────
    reg [127:0] aes_state;
    reg [127:0] rk;
    reg [127:0] orig_key;

    // ── Inlined SubBytes registers ───────────────────────────────────────────
    reg [4:0]   sub_cnt;        // 0=idle, 1-16=processing, 17=done
    reg [127:0] sub_shift;      // input state rotates through S-box
    reg [127:0] sub_accum;      // accumulates substituted bytes

    // sub_cnt==17 ← DONE, read sub_accum as SubBytes result
    wire sub_done = (sub_cnt == 5'd17);
    wire sub_busy = (sub_cnt >= 5'd1) && (sub_cnt <= 5'd16);

    // ── Single shared S-box for data SubBytes ────────────────────────────────
    wire [7:0] dsbox_in  = sub_shift[127:120];  // always MSB of shift reg
    wire [7:0] dsbox_out;
    aes_sbox_rom dsbox (.addr(dsbox_in), .data(dsbox_out));

    // ── Key expansion S-boxes (4 parallel, for SubWord) ─────────────────────
    wire [31:0] kx_w3   = rk[31:0];
    wire [31:0] kx_rot  = {kx_w3[23:0], kx_w3[31:24]};
    wire [31:0] kx_sub;
    aes_sbox_rom ks0(.addr(kx_rot[31:24]), .data(kx_sub[31:24]));
    aes_sbox_rom ks1(.addr(kx_rot[23:16]), .data(kx_sub[23:16]));
    aes_sbox_rom ks2(.addr(kx_rot[15:8]),  .data(kx_sub[15:8]));
    aes_sbox_rom ks3(.addr(kx_rot[7:0]),   .data(kx_sub[7:0]));

    wire [31:0]  kx_rcon = get_rcon(enc_ctr + 4'd1);
    wire [31:0]  kx_nw4  = rk[127:96] ^ kx_sub ^ kx_rcon;
    wire [31:0]  kx_nw5  = rk[95:64]  ^ kx_nw4;
    wire [31:0]  kx_nw6  = rk[63:32]  ^ kx_nw5;
    wire [31:0]  kx_nw7  = rk[31:0]   ^ kx_nw6;
    wire [127:0] next_rk = {kx_nw4, kx_nw5, kx_nw6, kx_nw7};

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

    // ── Combinational round ops (applied in S_ROUND from aes_state) ──────────
    wire [127:0] shift_out;
    wire [127:0] mix_out;
    ShiftRows  sr (.state_in(aes_state), .state_out(shift_out));
    MixColumns mc (.state_in(shift_out),  .state_out(mix_out));

    assign ready_in = (state == S_READY);

    // ── Main FSM + inlined SubBytes ──────────────────────────────────────────
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
        end else begin
            valid_out <= 1'b0;  // default

            // ── SubBytes counter (runs independently of FSM state) ──────────
            // Started by FSM when it needs SubBytes; runs to completion.
            if (sub_cnt == 5'd0) begin
                // idle — FSM will start it when needed (see below)
            end else if (sub_cnt == 5'd17) begin
                // Done cycle: aes_state captures result, FSM transitions
                sub_cnt <= 5'd0;
            end else begin
                // Processing cycle (cnt 1..16)
                // dsbox_in = sub_shift[127:120], dsbox_out = S(that byte)
                sub_shift <= {sub_shift[119:0], 8'h00};          // rotate left
                sub_accum <= {sub_accum[119:0], dsbox_out};       // accumulate
                if (sub_cnt == 5'd16)
                    sub_cnt <= 5'd17;   // signal done next cycle
                else
                    sub_cnt <= sub_cnt + 5'd1;
            end

            // ── Main FSM ─────────────────────────────────────────────────────
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
                        // Initial ARK then start SubBytes
                        // Load sub_shift with PT^RK0 so SubBytes runs on it
                        sub_shift <= plaintext_in ^ rk;  // PT ^ RK0
                        sub_accum <= 128'h0;
                        sub_cnt   <= 5'd1;               // start SubBytes immediately
                        aes_state <= plaintext_in ^ rk;  // keep a copy in aes_state
                        // Advance key to RK1
                        rk        <= next_rk;            // enc_ctr=0 → rcon[1] → RK1
                        enc_ctr   <= 4'd1;
                        state     <= S_SUBBYTES;
                    end
                end

                S_SUBBYTES: begin
                    // Wait until SubBytes finishes (sub_cnt reaches 17)
                    if (sub_done) begin
                        // sub_accum = SubBytes(aes_state) -- result is ready
                        aes_state <= sub_accum;
                        state     <= S_ROUND;
                    end
                end

                S_ROUND: begin
                    // aes_state = SubBytes result
                    // shift_out = ShiftRows(aes_state)  [combinational]
                    // mix_out   = MixCols(shift_out)    [combinational]
                    if (enc_ctr <= 4'd9) begin
                        // Standard round: MixCols + ARK, then start next SubBytes
                        sub_shift <= mix_out ^ rk;    // next round's input
                        sub_accum <= 128'h0;
                        sub_cnt   <= 5'd1;            // start SubBytes immediately
                        aes_state <= mix_out ^ rk;    // copy for ShiftRows/MC
                        rk        <= next_rk;
                        enc_ctr   <= enc_ctr + 4'd1;
                        state     <= S_SUBBYTES;
                    end else begin
                        // Final round: ShiftRows + ARK (no MixCols)
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
