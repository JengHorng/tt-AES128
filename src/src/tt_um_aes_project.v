`timescale 1ns / 1ps


module tt_um_aes_project (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,

    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,

    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);



    assign uio_oe  = 8'h00;
    assign uio_out = 8'h00;

    wire [3:0] byte_index;
    wire       select_plaintext;
    wire       write_en;
    wire       load_key_cmd;
    wire       start_cmd;

    assign byte_index       = uio_in[3:0];
    assign select_plaintext = uio_in[4];
    assign write_en         = uio_in[5];
    assign load_key_cmd     = uio_in[6];
    assign start_cmd        = uio_in[7];

    reg [127:0] key_reg;
    reg [127:0] plaintext_reg;


    reg key_load;
    reg valid_in;

    wire key_ready;
    wire ready_in;
    wire valid_out;

    wire [127:0] ciphertext_wire;


    reg [127:0] ciphertext_latch;

 
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg          <= 128'd0;
            plaintext_reg    <= 128'd0;
            ciphertext_latch <= 128'd0;
            key_load         <= 1'b0;
            valid_in         <= 1'b0;
        end else begin

            // Default: command pulses are only one clock cycle
            key_load <= 1'b0;
            valid_in <= 1'b0;

            if (write_en) begin
                if (select_plaintext == 1'b0) begin
                    case (byte_index)
                        4'd0:  key_reg[127:120] <= ui_in;
                        4'd1:  key_reg[119:112] <= ui_in;
                        4'd2:  key_reg[111:104] <= ui_in;
                        4'd3:  key_reg[103:96]  <= ui_in;
                        4'd4:  key_reg[95:88]   <= ui_in;
                        4'd5:  key_reg[87:80]   <= ui_in;
                        4'd6:  key_reg[79:72]   <= ui_in;
                        4'd7:  key_reg[71:64]   <= ui_in;
                        4'd8:  key_reg[63:56]   <= ui_in;
                        4'd9:  key_reg[55:48]   <= ui_in;
                        4'd10: key_reg[47:40]   <= ui_in;
                        4'd11: key_reg[39:32]   <= ui_in;
                        4'd12: key_reg[31:24]   <= ui_in;
                        4'd13: key_reg[23:16]   <= ui_in;
                        4'd14: key_reg[15:8]    <= ui_in;
                        4'd15: key_reg[7:0]     <= ui_in;
                        default: key_reg <= key_reg;
                    endcase
                end else begin
                    case (byte_index)
                        4'd0:  plaintext_reg[127:120] <= ui_in;
                        4'd1:  plaintext_reg[119:112] <= ui_in;
                        4'd2:  plaintext_reg[111:104] <= ui_in;
                        4'd3:  plaintext_reg[103:96]  <= ui_in;
                        4'd4:  plaintext_reg[95:88]   <= ui_in;
                        4'd5:  plaintext_reg[87:80]   <= ui_in;
                        4'd6:  plaintext_reg[79:72]   <= ui_in;
                        4'd7:  plaintext_reg[71:64]   <= ui_in;
                        4'd8:  plaintext_reg[63:56]   <= ui_in;
                        4'd9:  plaintext_reg[55:48]   <= ui_in;
                        4'd10: plaintext_reg[47:40]   <= ui_in;
                        4'd11: plaintext_reg[39:32]   <= ui_in;
                        4'd12: plaintext_reg[31:24]   <= ui_in;
                        4'd13: plaintext_reg[23:16]   <= ui_in;
                        4'd14: plaintext_reg[15:8]    <= ui_in;
                        4'd15: plaintext_reg[7:0]     <= ui_in;
                        default: plaintext_reg <= plaintext_reg;
                    endcase
                end
            end

            if (load_key_cmd) begin
                key_load <= 1'b1;
            end

          
            if (start_cmd && ready_in) begin
                valid_in <= 1'b1;
            end

            if (valid_out) begin
                ciphertext_latch <= ciphertext_wire;
            end
        end
    end


    aes_top aes_core (
        .clk            (clk),
        .rst_n          (rst_n),

        .key_in         (key_reg),
        .key_load       (key_load),
        .key_ready      (key_ready),

        .plaintext_in   (plaintext_reg),
        .valid_in       (valid_in),
        .ready_in       (ready_in),

        .ciphertext_out (ciphertext_wire),
        .valid_out      (valid_out),

        // Current AES pipeline is free-running.
        // Keep ready_out high.
        .ready_out      (1'b1)
    );


    reg [7:0] ciphertext_byte;

    always @(*) begin
        case (byte_index)
            4'd0:  ciphertext_byte = ciphertext_latch[127:120];
            4'd1:  ciphertext_byte = ciphertext_latch[119:112];
            4'd2:  ciphertext_byte = ciphertext_latch[111:104];
            4'd3:  ciphertext_byte = ciphertext_latch[103:96];
            4'd4:  ciphertext_byte = ciphertext_latch[95:88];
            4'd5:  ciphertext_byte = ciphertext_latch[87:80];
            4'd6:  ciphertext_byte = ciphertext_latch[79:72];
            4'd7:  ciphertext_byte = ciphertext_latch[71:64];
            4'd8:  ciphertext_byte = ciphertext_latch[63:56];
            4'd9:  ciphertext_byte = ciphertext_latch[55:48];
            4'd10: ciphertext_byte = ciphertext_latch[47:40];
            4'd11: ciphertext_byte = ciphertext_latch[39:32];
            4'd12: ciphertext_byte = ciphertext_latch[31:24];
            4'd13: ciphertext_byte = ciphertext_latch[23:16];
            4'd14: ciphertext_byte = ciphertext_latch[15:8];
            4'd15: ciphertext_byte = ciphertext_latch[7:0];
            default: ciphertext_byte = 8'h00;
        endcase
    end

    assign uo_out = ciphertext_byte;

    wire _unused;
    assign _unused = ena | key_ready | ready_in | valid_out;

endmodule