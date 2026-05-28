module addroundkey (
    input  wire [127:0] state_in,    // 128-bit AES state input
    input  wire [127:0] round_key,   // 128-bit round key
    output wire [127:0] state_out    // 128-bit AES state output
);

    // AES AddRoundKey operation:
    // output = state XOR round key
    assign state_out = state_in ^ round_key;

endmodule