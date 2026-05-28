module StandardRound (
	input wire 				clk,
	input wire [127:0]	state_in,
	input wire [127:0]	expanded_key, // expanded round_key to add
	output reg [127:0]	state_out
	);
	
	// connections between modules
	wire [127:0] sub_out;
	wire [127:0] shift_out;
	wire [127:0] mix_out;
	
	// carries out the regular rounds
	subbytes sub (
		.state_in(state_in),
		.state_out(sub_out)
		);
	
	ShiftRows shift (
		.state_in(sub_out),
		.state_out(shift_out)
		);
	
	MixColumns mix (
		.clk(clk),
		.state_in(shift_out),
		.state_out(mix_out)
		);
		
	// add round key
	always @(posedge clk) begin
		state_out <= mix_out ^ expanded_key;
	end
endmodule
	
