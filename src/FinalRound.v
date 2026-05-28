module FinalRound (
	input wire 				clk,
	input wire [127:0]	state_in,
	input wire [127:0]	expanded_key, // expanded round_key to add
	output reg [127:0]	state_out
	);
	
	// connections between modules
	wire [127:0] sub_out;
	wire [127:0] shift_out;
	
	// carries out the regular rounds
	subbytes sub (
		.state_in(state_in),
		.state_out(sub_out)
		);
	
	ShiftRows shift (
		.state_in(sub_out),
		.state_out(shift_out)
		);
		
	// delay reg for synchronizing on behalf of missing mix columns
	reg [127:0] delay_1;
	reg [127:0] delay_2;
	
	always @(posedge clk) begin
		// synchronization
		delay_1 <= shift_out;
		delay_2 <= delay_1;
		
		// add round key
		state_out <= delay_2 ^ expanded_key;
	end
endmodule
	
