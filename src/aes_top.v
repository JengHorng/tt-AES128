`timescale 1ns/1ps

module aes_top (
    input  wire         clk,
    input  wire         rst_n,

    // Key loading interface
    input  wire [127:0] key_in,  //input to be operate 
    input  wire         key_load, //load in operation 
    output reg          key_ready, // roundkey finish and can send plaintext

    input  wire [127:0] plaintext_in, //input 
    input  wire         valid_in, //1 if sender already send the input
    output wire         ready_in, // 1 if aes ready to accept input

    // Streaming output interface
    output wire [127:0] ciphertext_out,//output
    output wire         valid_out, //1 if operation done
    input  wire         ready_out  // 1 if Consumer ready to take ciphertext
);


    localparam PIPELINE_DEPTH = 31; 
	 //Initial AddRoundKey register = 1 cycle

	 //9 StandardRound modules × 3 cycles each = 27 cycles 
	 //FinalRound = 3 cycles 
	

    localparam S_IDLE   = 2'd0; //waiting for key
    localparam S_EXPAND = 2'd1; // generate RoundKey1 to RoundKey10
    localparam S_READY  = 2'd2; //roundkey operation done 

    reg [1:0] state;

    reg [127:0] round_keys [0:10];

    reg [127:0] current_key;//current key for key expansion
    reg [3:0]   round_ctr;//which round isit

    wire [127:0] rk0;
    wire [127:0] rk1;
    wire [127:0] rk2;
    wire [127:0] rk3;
    wire [127:0] rk4;
    wire [127:0] rk5;
    wire [127:0] rk6;
    wire [127:0] rk7;
    wire [127:0] rk8;
    wire [127:0] rk9;
    wire [127:0] rk10;

    assign rk0  = round_keys[0];
    assign rk1  = round_keys[1];
    assign rk2  = round_keys[2];
    assign rk3  = round_keys[3];
    assign rk4  = round_keys[4];
    assign rk5  = round_keys[5];
    assign rk6  = round_keys[6];
    assign rk7  = round_keys[7];
    assign rk8  = round_keys[8];
    assign rk9  = round_keys[9];
    assign rk10 = round_keys[10];

	//key expansion wire
    wire [31:0] kx_w0;
    wire [31:0] kx_w1;
    wire [31:0] kx_w2;
    wire [31:0] kx_w3;
	
    wire [31:0] kx_rot_word;//rotate last word
    wire [31:0] kx_sub_word;//sub operation
    wire [31:0] kx_temp;//XOR

    wire [31:0] kx_w4;
    wire [31:0] kx_w5;
    wire [31:0] kx_w6;
    wire [31:0] kx_w7;

    wire [127:0] kx_next_key;//next round key
    wire [31:0]  kx_rcon;//AES round constant 

    assign kx_w0 = current_key[127:96];
    assign kx_w1 = current_key[95:64];
    assign kx_w2 = current_key[63:32];
    assign kx_w3 = current_key[31:0];

    // RotWord
    assign kx_rot_word = {kx_w3[23:0], kx_w3[31:24]};

    // SubWord
    aes_sbox_rom kx_sbox0 (.addr(kx_rot_word[31:24]), .data(kx_sub_word[31:24]));
    aes_sbox_rom kx_sbox1 (.addr(kx_rot_word[23:16]), .data(kx_sub_word[23:16]));
    aes_sbox_rom kx_sbox2 (.addr(kx_rot_word[15:8]),  .data(kx_sub_word[15:8]));
    aes_sbox_rom kx_sbox3 (.addr(kx_rot_word[7:0]),   .data(kx_sub_word[7:0]));

    assign kx_rcon    = get_rcon(round_ctr); //Use the current round number round_ctr to select the correct AES Rcon value, then store that value in kx_rcon
    assign kx_temp    = kx_sub_word ^ kx_rcon;
    assign kx_w4      = kx_w0 ^ kx_temp;
    assign kx_w5      = kx_w1 ^ kx_w4;
    assign kx_w6      = kx_w2 ^ kx_w5;
    assign kx_w7      = kx_w3 ^ kx_w6;
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
            state     <= S_IDLE;
            key_ready <= 1'b0;
            round_ctr <= 4'd0;
        end else begin
            case (state)

                S_IDLE: begin
                    key_ready <= 1'b0;
                    if (key_load) begin
                        round_keys[0] <= key_in;
                        current_key   <= key_in;
                        round_ctr     <= 4'd1;
                        state         <= S_EXPAND;
                    end
                end

                S_EXPAND: begin
                    round_keys[round_ctr] <= kx_next_key;
                    current_key           <= kx_next_key;

                    if (round_ctr == 4'd10) begin
                        key_ready <= 1'b1;
                        state     <= S_READY;
                    end else begin
                        round_ctr <= round_ctr + 4'd1;
                    end
                end

                S_READY: begin
                    key_ready <= 1'b1;
                    if (key_load) begin 
                        key_ready     <= 1'b0; //check keyload see if another key entered without reseting all AES core
                        round_keys[0] <= key_in;
                        current_key   <= key_in;
                        round_ctr     <= 4'd1;
                        state         <= S_EXPAND;
                    end
                end

                default: begin
                    state     <= S_IDLE;
                    key_ready <= 1'b0;
                    round_ctr <= 4'd0;
                end

            endcase
        end
    end



    assign ready_in = (state == S_READY); //ready in=1


    wire accept_in = valid_in & ready_in; //valid in =1 when plaintext is entered


    reg [PIPELINE_DEPTH-1:0] valid_pipe;
	 //tracking real ciphertext using plaintext

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            valid_pipe <= {PIPELINE_DEPTH{1'b0}};
        end else if (key_load) begin//clear the pipe when new key is loaded
            valid_pipe <= {PIPELINE_DEPTH{1'b0}};
        end else begin
            valid_pipe <= {valid_pipe[PIPELINE_DEPTH-2:0], accept_in};
        end
    end

    wire pipe_valid = valid_pipe[PIPELINE_DEPTH-1];


    wire [127:0] ark0_out;
    reg  [127:0] stage0_out;   

    addroundkey initial_addroundkey (
        .state_in  (plaintext_in),
        .round_key (rk0),
        .state_out (ark0_out)
    );

    always @(posedge clk) begin   
        stage0_out <= ark0_out;
    end


    wire [127:0] round1_out;
    wire [127:0] round2_out;
    wire [127:0] round3_out;
    wire [127:0] round4_out;
    wire [127:0] round5_out;
    wire [127:0] round6_out;
    wire [127:0] round7_out;
    wire [127:0] round8_out;
    wire [127:0] round9_out;

    StandardRound round1 (.clk(clk), .state_in(stage0_out), .expanded_key(rk1),  .state_out(round1_out));
    StandardRound round2 (.clk(clk), .state_in(round1_out), .expanded_key(rk2),  .state_out(round2_out));
    StandardRound round3 (.clk(clk), .state_in(round2_out), .expanded_key(rk3),  .state_out(round3_out));
    StandardRound round4 (.clk(clk), .state_in(round3_out), .expanded_key(rk4),  .state_out(round4_out));
    StandardRound round5 (.clk(clk), .state_in(round4_out), .expanded_key(rk5),  .state_out(round5_out));
    StandardRound round6 (.clk(clk), .state_in(round5_out), .expanded_key(rk6),  .state_out(round6_out));
    StandardRound round7 (.clk(clk), .state_in(round6_out), .expanded_key(rk7),  .state_out(round7_out));
    StandardRound round8 (.clk(clk), .state_in(round7_out), .expanded_key(rk8),  .state_out(round8_out));
    StandardRound round9 (.clk(clk), .state_in(round8_out), .expanded_key(rk9),  .state_out(round9_out));


    wire [127:0] pipeline_ct;   

    FinalRound final_round (
        .clk         (clk),
        .state_in    (round9_out),
        .expanded_key(rk10),
        .state_out   (pipeline_ct)
    );



    reg [127:0] out_hold_reg;  //buffer that store cipher if receiver not ready yet   
    reg         out_hold_valid; //tel valid or not   
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            out_hold_valid <= 1'b0;
        end else begin
            if (key_load) begin //new key loaded then clear 
                out_hold_valid <= 1'b0;
            end else if (pipe_valid && !ready_out) begin
                out_hold_valid <= 1'b1;
            end else if (out_hold_valid && ready_out && !pipe_valid) begin //after present cipher and no new cipher arrived
                out_hold_valid <= 1'b0;
            end
 
        end
    end

    always @(posedge clk) begin   
        if (pipe_valid && !out_hold_valid) begin//store pipeline_ct into out_hold_reg
            out_hold_reg <= pipeline_ct;
        end
    end

    assign ciphertext_out = out_hold_valid ? out_hold_reg : pipeline_ct; 

    assign valid_out = out_hold_valid | pipe_valid;

endmodule
