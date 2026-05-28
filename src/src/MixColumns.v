// Parts of the module have been taken from GitHub by Michaelehab
// Link to GitHub: https://github.com/michaelehab/AES-Verilog/blob/main/mixColumns.v

module MixColumns (
    input  wire         clk, // clk for pipelining
    input  wire [127:0] state_in,
    output reg  [127:0] state_out
);

	 // function for multiplying by 2 in Galois
    function [7:0] mb2; 
        input [7:0] x;
        begin 
            if(x[7] == 1) mb2 = ((x << 1) ^ 8'h1b);
            else mb2 = x << 1; 
        end     
    endfunction

	 // function for multiplying by 3 in Galois
    function [7:0] mb3; 
        input [7:0] x;
        begin 
            mb3 = mb2(x) ^ x;
        end 
    endfunction

    //generate the hardware 4 times for parallel processing
    genvar i;
    generate 
        for(i=0; i<4; i=i+1) begin : m_col

            // intermediate registers for stage 1 (multiplication)
            reg [7:0] ori3, ori2, ori1, ori0;
            reg [7:0] mb2_3, mb2_2, mb2_1, mb2_0;
            reg [7:0] mb3_3, mb3_2, mb3_1, mb3_0;

            // stage 1 - calculate the multipliers and save them in the intermediate registers
            always @(posedge clk) begin
                // the original bytes
                ori3 <= state_in[(i*32 + 24)+:8];
                ori2 <= state_in[(i*32 + 16)+:8];
                ori1 <= state_in[(i*32 +  8)+:8];
                ori0 <= state_in[(i*32 +  0)+:8];

                // multiply by 2, bytes
                mb2_3 <= mb2(state_in[(i*32 + 24)+:8]);
                mb2_2 <= mb2(state_in[(i*32 + 16)+:8]);
                mb2_1 <= mb2(state_in[(i*32 +  8)+:8]);
                mb2_0 <= mb2(state_in[(i*32 +  0)+:8]);

                // multiply by 3, bytes
                mb3_3 <= mb3(state_in[(i*32 + 24)+:8]);
                mb3_2 <= mb3(state_in[(i*32 + 16)+:8]);
                mb3_1 <= mb3(state_in[(i*32 +  8)+:8]);
                mb3_0 <= mb3(state_in[(i*32 +  0)+:8]);
            end

            // stage 2 - XOR tree operation
            always @(posedge clk) begin
                state_out[(i*32 + 24)+:8] <= mb2_3 ^ mb3_2 ^ ori1 ^ ori0;
                state_out[(i*32 + 16)+:8] <= ori3 ^ mb2_2 ^ mb3_1 ^ ori0;
                state_out[(i*32 +  8)+:8] <= ori3 ^ ori2 ^ mb2_1 ^ mb3_0;
                state_out[(i*32 +  0)+:8] <= mb3_3 ^ ori2 ^ ori1 ^ mb2_0;
            end

        end
    endgenerate

endmodule