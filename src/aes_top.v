`timescale 1ns/1ps

module aes_top (
    input  wire         clk,
    input  wire         rst_n,

    // Key loading interface
    input  wire [127:0] key_in,
    input  wire         key_load,
    output reg          key_ready,

    input  wire [127:0] plaintext_in,
    input  wire         valid_in,
    output wire         ready_in,

    // Streaming output interface
    output wire [127:0] ciphertext_out,
    output wire         valid_out,
    input  wire         ready_out
);

    // ============================================================
    // KEY EXPANSION FSM
    // ============================================================

    localparam K_IDLE   = 2'd0;
    localparam K_EXPAND = 2'd1;
    localparam K_READY  = 2'd2;

    reg [1:0] key_state;

    reg [127:0] round_keys [0:10];
    reg [127:0] current_key;
    reg [3:0]   round_ctr;

    wire [31:0] kx_w0;
    wire [31:0] kx_w1;
    wire [31:0] kx_w2;
    wire [31:0] kx_w3;

    wire [31:0] kx_rot_word;
    wire [31:0] kx_sub_word;
    wire [31:0] kx_temp;

    wire [31:0] kx_w4;
    wire [31:0] kx_w5;
    wire [31:0] kx_w6;
    wire [31:0] kx_w7;

    wire [127:0] kx_next_key;
    wire [31:0]  kx_rcon;

    assign kx_w0 = current_key[127:96];
    assign kx_w1 = current_key[95:64];
    assign kx_w2 = current_key[63:32];
    assign kx_w3 = current_key[31:0];

    // RotWord
    assign kx_rot_word = {kx_w3[23:0], kx_w3[31:24]};

    // SubWord, reuse aes_sbox_rom module from subbytes.v
    aes_sbox_rom kx_sbox0 (.addr(kx_rot_word[31:24]), .data(kx_sub_word[31:24]));
    aes_sbox_rom kx_sbox1 (.addr(kx_rot_word[23:16]), .data(kx_sub_word[23:16]));
    aes_sbox_rom kx_sbox2 (.addr(kx_rot_word[15:8]),  .data(kx_sub_word[15:8]));
    aes_sbox_rom kx_sbox3 (.addr(kx_rot_word[7:0]),   .data(kx_sub_word[7:0]));

    assign kx_rcon     = get_rcon(round_ctr);
    assign kx_temp     = kx_sub_word ^ kx_rcon;
    assign kx_w4       = kx_w0 ^ kx_temp;
    assign kx_w5       = kx_w1 ^ kx_w4;
    assign kx_w6       = kx_w2 ^ kx_w5;
    assign kx_w7       = kx_w3 ^ kx_w6;
    assign kx_next_key = {kx_w4, kx_w5, kx_w6, kx_w7};

    function [31:0] get_rcon;
        input [3:0] round;
        begin
            case (round)
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

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_state   <= K_IDLE;
            key_ready   <= 1'b0;
            round_ctr   <= 4'd0;
            current_key <= 128'd0;
        end else begin
            case (key_state)

                K_IDLE: begin
                    key_ready <= 1'b0;

                    if (key_load) begin
                        round_keys[0] <= key_in;
                        current_key   <= key_in;
                        round_ctr     <= 4'd1;
                        key_state     <= K_EXPAND;
                    end
                end

                K_EXPAND: begin
                    round_keys[round_ctr] <= kx_next_key;
                    current_key           <= kx_next_key;

                    if (round_ctr == 4'd10) begin
                        key_ready <= 1'b1;
                        key_state <= K_READY;
                    end else begin
                        round_ctr <= round_ctr + 4'd1;
                    end
                end

                K_READY: begin
                    key_ready <= 1'b1;

                    if (key_load) begin
                        key_ready     <= 1'b0;
                        round_keys[0] <= key_in;
                        current_key   <= key_in;
                        round_ctr     <= 4'd1;
                        key_state     <= K_EXPAND;
                    end
                end

                default: begin
                    key_state <= K_IDLE;
                    key_ready <= 1'b0;
                    round_ctr <= 4'd0;
                end

            endcase
        end
    end


    // ============================================================
    // ITERATIVE AES ENCRYPTION FSM
    // ============================================================
    //
    // Old design:
    //   round1, round2, round3, ..., round9, final_round all existed
    //   at the same time.
    //
    // New design:
    //   one StandardRound reused for round 1 to round 9.
    //   one FinalRound reused for final round.
    //
    // This reduces area a lot.
    // ============================================================

    localparam E_IDLE       = 3'd0;
    localparam E_STD_WAIT   = 3'd1;
    localparam E_STD_LATCH  = 3'd2;
    localparam E_FINAL_WAIT = 3'd3;
    localparam E_FINAL_DONE = 3'd4;
    localparam E_OUT_VALID  = 3'd5;

    reg [2:0] enc_state;

    reg [127:0] round_state;
    reg [3:0]   enc_round;
    reg [2:0]   wait_ctr;

    reg [127:0] ciphertext_reg;
    reg         ciphertext_valid;

    wire [127:0] std_round_out;
    wire [127:0] final_round_out;

    // One shared standard round hardware
    StandardRound standard_round_shared (
        .clk          (clk),
        .state_in     (round_state),
        .expanded_key (round_keys[enc_round]),
        .state_out    (std_round_out)
    );

    // One shared final round hardware
    FinalRound final_round_shared (
        .clk          (clk),
        .state_in     (round_state),
        .expanded_key (round_keys[10]),
        .state_out    (final_round_out)
    );

    assign ready_in = (key_state == K_READY) &&
                      (enc_state == E_IDLE) &&
                      (!ciphertext_valid);

    assign ciphertext_out = ciphertext_reg;
    assign valid_out      = ciphertext_valid;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            enc_state        <= E_IDLE;
            round_state      <= 128'd0;
            enc_round        <= 4'd0;
            wait_ctr         <= 3'd0;
            ciphertext_reg   <= 128'd0;
            ciphertext_valid <= 1'b0;
        end else begin

            // Clear output when receiver accepts it
            if (ciphertext_valid && ready_out) begin
                ciphertext_valid <= 1'b0;
            end

            // If a new key is loaded, cancel current encryption
            if (key_load) begin
                enc_state        <= E_IDLE;
                round_state      <= 128'd0;
                enc_round        <= 4'd0;
                wait_ctr         <= 3'd0;
                ciphertext_valid <= 1'b0;
            end else begin

                case (enc_state)

                    E_IDLE: begin
                        wait_ctr <= 3'd0;

                        if (valid_in && ready_in) begin
                            // Initial AddRoundKey
                            round_state <= plaintext_in ^ round_keys[0];

                            // Start AES standard round 1
                            enc_round   <= 4'd1;
                            wait_ctr    <= 3'd0;
                            enc_state   <= E_STD_WAIT;
                        end
                    end

                    E_STD_WAIT: begin
                        // StandardRound has internal registered stages.
                        // Original design counted each StandardRound as 3 cycles.
                        if (wait_ctr == 3'd3) begin
                            enc_state <= E_STD_LATCH;
                        end else begin
                            wait_ctr <= wait_ctr + 3'd1;
                        end
                    end

                    E_STD_LATCH: begin
                        // Capture output from shared StandardRound
                        round_state <= std_round_out;
                        wait_ctr    <= 3'd0;

                        if (enc_round == 4'd9) begin
                            // After round 9, go to final round
                            enc_state <= E_FINAL_WAIT;
                        end else begin
                            // Continue next standard round
                            enc_round <= enc_round + 4'd1;
                            enc_state <= E_STD_WAIT;
                        end
                    end

                    E_FINAL_WAIT: begin
                        // FinalRound also has internal delay registers.
                        // Original final round latency was treated as 3 cycles.
                        if (wait_ctr == 3'd3) begin
                            enc_state <= E_FINAL_DONE;
                        end else begin
                            wait_ctr <= wait_ctr + 3'd1;
                        end
                    end

                    E_FINAL_DONE: begin
                        ciphertext_reg   <= final_round_out;
                        ciphertext_valid <= 1'b1;
                        enc_state        <= E_OUT_VALID;
                    end

                    E_OUT_VALID: begin
                        // Hold ciphertext until receiver accepts it.
                        if (ciphertext_valid && ready_out) begin
                            enc_state <= E_IDLE;
                        end
                    end

                    default: begin
                        enc_state <= E_IDLE;
                    end

                endcase
            end
        end
    end

endmodule
