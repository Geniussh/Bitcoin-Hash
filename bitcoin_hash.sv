// `include "simplified_sha256.sv"

module bitcoin_hash(input logic 			clk, reset_n, start,
                          input logic [15:0] message_addr, output_addr,
                         output logic 			done, mem_clk, mem_we,
                         output logic [15:0] mem_addr,
                         output logic [31:0] mem_write_data,
                          input logic [31:0] mem_read_data);

parameter NUM_NONCES = 16;
parameter int nonces[0:15] = '{
    32'd0, 32'd1, 32'd2, 32'd3, 32'd4, 32'd5, 32'd6, 32'd7,
   32'd8, 32'd9, 32'd10, 32'd11, 32'd12, 32'd13, 32'd14, 32'd15
};

// states
enum logic [3:0] {  IDLE     = 4'b0000, 
                    READ1    = 4'b0001, 
                    READ2    = 4'b0010, 
                    BLOCK1   = 4'b0011,
                    BLOCK2   = 4'b0100, 
                    BLOCK3   = 4'b0101,
                    COMPUTE1 = 4'b0110, 
                    COMPUTE2 = 4'b0111, 
                    WRITE    = 4'b1000} state;

logic [31:0] sha[16];
logic [15:0] num;
logic [15:0] cnt_w;   // write counter address
logic [ 6:0] count;
logic [ 1:0] phase;   // 3 phases
                        
assign mem_clk = clk;

// Generate 16 SHA modules
genvar q;
generate
    for (q = 0; q < NUM_NONCES; q++) begin : generate_sha256
        simplified_sha256 sha256_module (
            .clk(clk),
            .reset_n(reset_n),
            .start(start),
            .state(state),
            .nonce(nonces[q]),
            .mem_read_data(mem_read_data),
            .hash(sha[q]));
    end
endgenerate

// main always_ff block for the FSM
always_ff@(posedge clk, negedge reset_n)
begin
    // when async reset is 0, reset ports and set state to IDLE
    if(!reset_n) begin
        done <= 0;
        num <= 0;
        cnt_w <= 0;
        state <= IDLE;
    end else begin
        // determine what to do depending on the current state
        case(state)
            // IDLE state: find address to read message and change state to 
            // READ1
            IDLE: begin
                if(start) begin	
                    mem_we <= 0;
                    mem_addr <= message_addr + num;
                    num <= num + 1;	
                    phase <= 0;
                    state <= READ1;
                end
            end

            // READ1 state: find new address to read message and change state to
            // READ2
            READ1: begin
                mem_addr <= message_addr + num;
                num <= num + 1;
                count <= 0;
                state <= READ2;
            end

            // READ2 state: find new address to read message and change state to
            // COMPUTE1
            READ2: begin
                mem_addr <= message_addr + num;
                num <= num + 1;
                state <= COMPUTE1;
            end

            // COMPUTE1 state: find new address to read message and change state
            // depending on the current phase
            COMPUTE1: begin
                mem_addr <= message_addr + num;
                num <= num + 1;
                count <= 1;
                if(phase == 1) state <= BLOCK2;
                else state <= BLOCK1;
            end

            // BLOCK1 state: read 14 messages; after 63 cycles, increment phase
            // and change state to COMPUTE2
            BLOCK1: begin
                if (count < 15) begin
                    mem_addr <= message_addr + num;
                    num <= num + 1;
                end
                count <= count + 1;	
                
                if(count == 64) begin
                    phase <= phase + 1;
                    state <= COMPUTE2;
                end else state <= BLOCK1;
            end	

            // BLOCK2 state: read 1 message; after 63 cycles, increment phase
            // and change state to COMPUTE2
            BLOCK2: begin
                if (count < 2) begin
                    mem_addr <= message_addr + num;
                    num <= num + 1;
                end
                count <= count + 1;
                                
                if(count == 64) begin
                    phase <= phase + 1;
                    state <= COMPUTE2;
                end else state <= BLOCK2;
            end	

            // BLOCK2 state: after 63 cycles, read message, increment phase and
            // change state to COMPUTE2
            BLOCK3: begin
                count <= count + 1;
                if(count == 64) begin
                    num <= 17;
                    mem_addr <= message_addr + 16;
                    phase <= phase + 1;
                    state <= COMPUTE2;
                end else state <= BLOCK3;
            end

            // COMPUTE2 state: depending on phase, change state and update
            COMPUTE2: begin
                // set num to 17, read message, and go to READ1 state in phase 1
                if(phase == 1) begin
                    num <= 17;
                    mem_addr <= message_addr + 16;
                    state<=READ1;
                end 
                // set count to 1 and go to BLOCK3 state
                else if(phase==2) begin
                    count <= 1;
                    state <= BLOCK3;
                end
                // reset count and go to WRITE state 
                else if(phase==3) begin
                    count <= 0;
                    state <= WRITE;
                end	
            end

            // WRITE state: write to memory
            WRITE: begin
                // indicating computation has been completed
                mem_we <= 1;
                // write hash values to corresponding memory addresses
                mem_addr <= output_addr + cnt_w;
                mem_write_data <= sha[count];
                cnt_w <= cnt_w + 1;
                count <= count + 1;
                
                // set done to 1 when all hash values are written
                if(cnt_w == 16) done<=1;
                else state<= WRITE;
            end
        endcase
    end
end

endmodule
