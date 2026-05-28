`timescale 1ns/1ps
// =============================================================================
// aes_top.v  —  Area-optimised iterative AES-128 core  (Tiny Tapeout version)
// =============================================================================
//
// AREA REDUCTION vs pipelined design:
//   Pipelined : ~5,556 FFs, 20 S-box instances (~16,000 cells)
//   This core :   ~530 FFs,  5 S-box instances (~4,500 cells) — fits 4×2 tile
//
// CHANGES vs previous iterative version:
//   subbytes   : sequential (1 shared instance, 16 cycles) vs 16 parallel
//   kx_sbox    : still 4 parallel (needed every round for key expansion)
//
// TIMING (181 cycles per encryption block):
//   Cycle  0       : initial AddRoundKey  (S_READY → S_SUBBYTES)
//   Cycles 1..171  : 9 × (1 sub_start + 16 SubBytes + 1 round_op) = 9×18 = 162
//   Cycles 172..188: final round  (1 sub_start + 16 SubBytes + 1 round_op)
//   Cycle  181     : valid_out=1, ciphertext ready → S_READY
//
// INTERFACE: identical to pipelined aes_top — tt_um_aes_project.v unchanged.
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

    // ─────────────────────────────────────────────────────────────────────────
    // FSM states
    // ─────────────────────────────────────────────────────────────────────────
    localparam S_IDLE     = 2'd0;
    localparam S_READY    = 2'd1;
    localparam S_SUBBYTES = 2'd2;   // waiting for sequential SubBytes
    localparam S_ROUND_OP = 2'd3;   // ShiftRows + MixColumns/ARK

    reg [1:0] state;

    // ─────────────────────────────────────────────────────────────────────────
    // Data registers (~530 FFs)
    // ─────────────────────────────────────────────────────────────────────────
    reg [127:0] aes_state;   // 128b — current AES state
    reg [127:0] rk;          // 128b — current round key
    reg [127:0] orig_key;    // 128b — RK0 (reset between blocks)
    reg [3:0]   enc_ctr;     //   4b — round counter 1..10

    // ─────────────────────────────────────────────────────────────────────────
    // Sequential SubBytes instance (1 shared aes_sbox_rom inside)
    // ─────────────────────────────────────────────────────────────────────────
    wire        sub_start;        // asserted combinationally
    wire [127:0] sub_state_out;
    wire         sub_done;
    wire         sub_busy;

    subbytes sb (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (sub_start),
        .state_in (aes_state),
        .state_out(sub_state_out),
        .done     (sub_done),
        .busy     (sub_busy)
    );

    // Start SubBytes on the FIRST cycle of S_SUBBYTES (before SubBytes is busy)
    assign sub_start = (state == S_SUBBYTES) && !sub_busy;

    // ─────────────────────────────────────────────────────────────────────────
    // Combinational round operations (applied to aes_state in S_ROUND_OP)
    // After S_SUBBYTES, aes_state holds the SubBytes result.
    // ─────────────────────────────────────────────────────────────────────────
    wire [127:0] shift_out;    // ShiftRows(aes_state)
    wire [127:0] mix_out;      // MixColumns(shift_out)

    ShiftRows   sr (.state_in(aes_state), .state_out(shift_out));
    MixColumns  mc (.state_in(shift_out), .state_out(mix_out));

    // ─────────────────────────────────────────────────────────────────────────
    // On-the-fly key expansion (4 parallel S-box instances for SubWord)
    // These 4 instances add ~3,200 cells but run combinationally every cycle.
    // ─────────────────────────────────────────────────────────────────────────
    wire [31:0] kx_w3   = rk[31:0];
    wire [31:0] kx_rot  = {kx_w3[23:0], kx_w3[31:24]};   // RotWord
    wire [31:0] kx_sub;                                     // SubWord

    aes_sbox_rom ks0 (.addr(kx_rot[31:24]), .data(kx_sub[31:24]));
    aes_sbox_rom ks1 (.addr(kx_rot[23:16]), .data(kx_sub[23:16]));
    aes_sbox_rom ks2 (.addr(kx_rot[15:8]),  .data(kx_sub[15:8]));
    aes_sbox_rom ks3 (.addr(kx_rot[7:0]),   .data(kx_sub[7:0]));

    wire [31:0] kx_rcon = get_rcon(enc_ctr + 4'd1);   // rcon indexed by CURRENT enc_ctr
    wire [31:0] kx_nw4  = rk[127:96] ^ kx_sub ^ kx_rcon;
    wire [31:0] kx_nw5  = rk[95:64]  ^ kx_nw4;
    wire [31:0] kx_nw6  = rk[63:32]  ^ kx_nw5;
    wire [31:0] kx_nw7  = rk[31:0]   ^ kx_nw6;
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

    // ─────────────────────────────────────────────────────────────────────────
    // ready_in — high when idle in S_READY
    // ─────────────────────────────────────────────────────────────────────────
    assign ready_in = (state == S_READY);

    // ─────────────────────────────────────────────────────────────────────────
    // Main FSM
    // ─────────────────────────────────────────────────────────────────────────
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_IDLE;
            key_ready     <= 1'b0;
            valid_out     <= 1'b0;
            enc_ctr       <= 4'd0;
            aes_state     <= 128'h0;
            rk            <= 128'h0;
            orig_key      <= 128'h0;
            ciphertext_out<= 128'h0;
        end else begin
            valid_out <= 1'b0;   // default

            case (state)

                // ─────────────────────────────────────────────────────────
                // S_IDLE — wait for key_load pulse
                // ─────────────────────────────────────────────────────────
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

                // ─────────────────────────────────────────────────────────
                // S_READY — accept plaintext, perform initial AddRoundKey
                //
                // When valid_in fires:
                //   aes_state = plaintext XOR RK0
                //   rk        = next_rk (RK1, using enc_ctr=1 rcon)
                //   enc_ctr   = 1
                //   → S_SUBBYTES (sub_start fires on first cycle there)
                // ─────────────────────────────────────────────────────────
                S_READY: begin
                    key_ready <= 1'b1;

                    if (key_load) begin
                        // Hot key reload
                        orig_key <= key_in;
                        rk       <= key_in;
                        enc_ctr  <= 4'd0;
                    end else if (valid_in) begin
                        // Initial AddRoundKey with RK0
                        aes_state <= plaintext_in ^ rk;

                        // Pre-expand key: next_rk = expand(RK0, rcon[1]) = RK1 (enc_ctr=0, so enc_ctr+1=1)
                        enc_ctr   <= 4'd1;
                        rk        <= next_rk;   // next_rk = expand(RK0, rcon[1]) = RK1

                        state     <= S_SUBBYTES;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // S_SUBBYTES — sequential SubBytes processing
                //
                // sub_start fires automatically on first cycle (!sub_busy).
                // Wait for sub_done, then capture result into aes_state.
                // ─────────────────────────────────────────────────────────
                S_SUBBYTES: begin
                    if (sub_done) begin
                        aes_state <= sub_state_out;
                        state     <= S_ROUND_OP;
                    end
                end

                // ─────────────────────────────────────────────────────────
                // S_ROUND_OP — apply ShiftRows + MixColumns/ARK
                //
                // aes_state holds SubBytes result.
                // Combinational: shift_out = ShiftRows(aes_state)
                //                mix_out   = MixColumns(shift_out)
                //
                // Rounds 1-9 (standard): aes_state = mix_out XOR rk
                // Round 10  (final)    : ciphertext = shift_out XOR rk
                // ─────────────────────────────────────────────────────────
                S_ROUND_OP: begin
                    if (enc_ctr <= 4'd9) begin
                        // Standard round: include MixColumns
                        aes_state <= mix_out ^ rk;
                        rk        <= next_rk;          // advance key
                        enc_ctr   <= enc_ctr + 4'd1;
                        state     <= S_SUBBYTES;

                    end else begin
                        // Final round (enc_ctr=10): no MixColumns
                        ciphertext_out <= shift_out ^ rk;
                        valid_out      <= 1'b1;
                        rk             <= orig_key;    // reset for next block
                        enc_ctr        <= 4'd0;
                        state          <= S_READY;
                    end
                end

                default: state <= S_IDLE;

            endcase
        end
    end

endmodule
