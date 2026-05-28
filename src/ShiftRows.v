module ShiftRows (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    // AES states are populated column by column.

    // Column 0
    wire [7:0] b00 = state_in[127:120];
    wire [7:0] b01 = state_in[119:112];
    wire [7:0] b02 = state_in[111:104];
    wire [7:0] b03 = state_in[103:96];

    // Column 1
    wire [7:0] b04 = state_in[95:88];
    wire [7:0] b05 = state_in[87:80];
    wire [7:0] b06 = state_in[79:72];
    wire [7:0] b07 = state_in[71:64];

    // Column 2
    wire [7:0] b08 = state_in[63:56];
    wire [7:0] b09 = state_in[55:48];
    wire [7:0] b10 = state_in[47:40];
    wire [7:0] b11 = state_in[39:32];

    // Column 3
    wire [7:0] b12 = state_in[31:24];
    wire [7:0] b13 = state_in[23:16];
    wire [7:0] b14 = state_in[15:8];
    wire [7:0] b15 = state_in[7:0];
    
	 // Export column - wise for easier operation of MixColumns
	 
    assign state_out = {
        b00, b05, b10, b15,
        b04, b09, b14, b03,
        b08, b13, b02, b07,
        b12, b01, b06, b11
    };

endmodule