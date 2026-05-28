`timescale 1ns/1ps
// =============================================================================
// subbytes.v  —  Sequential AES SubBytes  (Tiny Tapeout version)
// =============================================================================
// Uses ONE shared aes_sbox_rom instance instead of 16 parallel instances.
//
// Area comparison (sky130):
//   Parallel (original) : 16 × 800 cells = 12,800 cells
//   Sequential (this)   :  1 × 800 cells =    800 cells  (16× smaller)
//
// Interface:
//   start  — 1-cycle pulse to begin processing
//   state_in — 128-bit AES state to substitute (must be stable when start fires)
//   state_out — substituted state (valid when done fires)
//   done   — 1-cycle pulse, fires 16 cycles after start
//   busy   — high while processing (start ignored when busy=1)
//
// Timing: start at T → done at T+16 (16 clock cycles)
// =============================================================================

module subbytes (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [127:0] state_in,
    output reg  [127:0] state_out,
    output reg          done,
    output reg          busy
);

    reg [127:0] shift_reg;   // input state shifts through the S-box
    reg [3:0]   cnt;         // byte counter: 0..15

    // Single shared S-box — always fed from MSB of shift register
    wire [7:0] sbox_in  = shift_reg[127:120];
    wire [7:0] sbox_out;
    aes_sbox_rom rom (.addr(sbox_in), .data(sbox_out));

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            shift_reg <= 128'h0;
            state_out <= 128'h0;
            done      <= 1'b0;
            busy      <= 1'b0;
            cnt       <= 4'd0;
        end else begin
            done <= 1'b0;   // default: done is a 1-cycle pulse

            if (start && !busy) begin
                // ── Latch phase ─────────────────────────────────────────────
                // Capture input state; processing begins next cycle
                shift_reg <= state_in;
                state_out <= 128'h0;
                cnt       <= 4'd0;
                busy      <= 1'b1;

            end else if (busy) begin
                // ── Process phase ───────────────────────────────────────────
                // Each cycle: substitute MSB byte of shift_reg, rotate left,
                // accumulate result into state_out (building MSB-first).
                //
                // Cycle cnt=0 : sbox(byte_0)  → state_out[7:0]
                // Cycle cnt=1 : sbox(byte_1)  → state_out[15:8]  (byte_0 shifts to [15:8])
                // ...
                // Cycle cnt=15: sbox(byte_15) → state_out[7:0]
                // After 16 shifts: state_out = {S(b0), S(b1), ..., S(b15)} ✓

                shift_reg <= {shift_reg[119:0], 8'h00};         // rotate left 8
                state_out <= {state_out[119:0], sbox_out};       // accumulate

                if (cnt == 4'd15) begin
                    done <= 1'b1;
                    busy <= 1'b0;
                    cnt  <= 4'd0;
                end else begin
                    cnt <= cnt + 4'd1;
                end
            end
        end
    end

endmodule
