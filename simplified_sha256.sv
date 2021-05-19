// Adjusted SHA256 MODULE for Bitcoin Hash
module simplified_sha256(input logic   		clk, reset_n, start, 
                                 input logic  [ 3:0] state,
                                 input logic  [31:0] nonce,
                                 input logic  [31:0] mem_read_data,
                                output logic  [31:0] hash);

// states
parameter int IDLE     = 4'b0000;
parameter int READ1    = 4'b0001;
parameter int READ2    = 4'b0010;
parameter int BLOCK1   = 4'b0011;
parameter int BLOCK2   = 4'b0100;
parameter int BLOCK3   = 4'b0101;
parameter int COMPUTE1 = 4'b0110;
parameter int COMPUTE2 = 4'b0111;
parameter int WRITE    = 4'b1000;

logic [31:0] w[16];
logic [31:0] H[8];
logic [31:0] a, b, c, d, e, f, g, h, P;
logic [ 6:0] num;
logic [ 1:0] phase;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// SHA256 hash round -- precomputing "h+k+w = p"
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, P);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
    begin
         S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
         ch = (e & f) ^ ((~e) & g);
         t1 = S1 + ch + P;
         S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
         maj = (a & b) ^ (a & c) ^ (b & c);
         t2 = S0 + maj;
         sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
    end
endfunction

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
begin
    rightrotate = (x >> r) | (x << (32 - r));
end
endfunction

//function to compute new Wt
function logic [31:0] get_w15(); 
    logic [31:0] S0, S1;
    S0 = rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1] >> 3); 
    S1 = rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10); 
    get_w15 = w[0] + S0 + w[9] + S1; 
endfunction

// main always_ff block for the FSM
always_ff@(posedge clk, negedge reset_n)
begin
    if(!reset_n) begin
        // Do nothing
    end 
    else case(state)
        // when bitcoin's state is IDLE, reset values
        IDLE: begin
            if(start) begin
                H[0] <= 32'h6a09e667;
                H[1] <= 32'hbb67ae85;
                H[2] <= 32'h3c6ef372;
                H[3] <= 32'ha54ff53a;
                H[4] <= 32'h510e527f;
                H[5] <= 32'h9b05688c;
                H[6] <= 32'h1f83d9ab;
                H[7] <= 32'h5be0cd19;	
                
                a <= 32'h6a09e667;
                b <= 32'hbb67ae85;
                c <= 32'h3c6ef372;
                d <= 32'ha54ff53a;
                e <= 32'h510e527f;
                f <= 32'h9b05688c;
                g <= 32'h1f83d9ab;
                h <= 32'h5be0cd19;

                phase <= 0;
            end
        end

        // when bitcoin's state is READ1, reset num
        READ1: begin
            num <= 0;
        end

        // when bitcoin's state is READ2, read data to index 15 of w
        READ2: begin
            w[15] <= mem_read_data;
        end

        // when bitcoin's state is COMPUTE1, compute P, read data to index 15 of
        // w and right shift on w
        COMPUTE1: begin	
            P <= k[num] + H[7] + w[15];
            w[15] <= mem_read_data;
            for (int i = 0; i < 15; i++) w[i] <= w[i + 1];
            num <= 1;
        end

        // when bitcoin's state is BLOCK1, compute data
        BLOCK1: begin
            // read data to index 15 of w 14 times
            if (num < 15) w[15] <= mem_read_data;
            // compute index 15 of w using helper function
            else w[15] <= get_w15();
            // right shift w
            for (int i = 0; i < 15; i++) w[i] <= w[i + 1];
            // compute a-h and P
            P <= k[num] + w[15] + g;
            {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, P);
            num <= num + 1;	
            // increment phase after 63 cycles
            if(num == 64) phase <= phase + 1;
        end
        
        // when bitcoin's state is BLOCK2, compute data
        BLOCK2: begin
            // set data for index 15 of w depending on num
            if (num < 2) w[15] <= mem_read_data;
            else if (num == 2) w[15] <= nonce;
            else if (num == 3) w[15] <= 32'h80000000;
            else if (num < 14) w[15] <= 32'h00000000;
            else if (num == 14) w[15] <= 32'd640;
            else w[15] <= get_w15();
            // right shift w
            for (int i = 0; i < 15; i++) w[i] <= w[i + 1];
            // compute a-h and P
            P <= k[num] + w[15] + g;
            {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, P);
            num <= num + 1;
            // increment phase after 63 cycles
            if(num == 64) phase <= phase + 1;
        end

        // when bitcoin's state is BLOCK3, compute data
        BLOCK3: begin
            // Append 1; Pad 0's; Append message length
            if (num < 7) w[15] <= H[num+1];
            else if (num == 7) w[15] <= 32'h80000000;
            else if (num < 14) w[15] <= 32'h00000000;
            else if (num == 14) w[15] <= 32'd256;
            else w[15] <= get_w15();
            // right shift w
            for (int i = 0; i < 15; i++) w[i] <= w[i + 1];
            // compute a-h and P
            P <= k[num] + w[15] + g;
            {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, P);
            num <= num + 1;
            // increment phase and reset hash values after 63 cycles
            if(num == 64) begin
                phase <= phase + 1;
                H[0] <= 32'h6a09e667;
                H[1] <= 32'hbb67ae85;
                H[2] <= 32'h3c6ef372;
                H[3] <= 32'ha54ff53a;
                H[4] <= 32'h510e527f;
                H[5] <= 32'h9b05688c;
                H[6] <= 32'h1f83d9ab;
                H[7] <= 32'h5be0cd19;
            end
        end
        
        // when bitcoin's state is COMPUTE2, compute hash values
        COMPUTE2: begin
            H[0] <= a + H[0];
            H[1] <= b + H[1];
            H[2] <= c + H[2];
            H[3] <= d + H[3];
            H[4] <= e + H[4];
            H[5] <= f + H[5];
            H[6] <= g + H[6];
            H[7] <= h + H[7];

            a <= a + H[0];
            b <= b + H[1];
            c <= c + H[2];
            d <= d + H[3];
            e <= e + H[4];
            f <= f + H[5];
            g <= g + H[6];
            h <= h + H[7];

            // when in phase 2, reset a-h, and compute P and w
            if(phase == 2) begin
                a <= 32'h6a09e667;
                b <= 32'hbb67ae85;
                c <= 32'h3c6ef372;
                d <= 32'ha54ff53a;
                e <= 32'h510e527f;
                f <= 32'h9b05688c;
                g <= 32'h1f83d9ab;
                h <= 32'h5be0cd19;
                P <= k[0] + 32'h5be0cd19 + a + H[0];
                w[14] <= H[0] + a;
                w[15] <= H[1] + b;
                num <= 1;
            end else if(phase==3) hash <= a + H[0]; // Output
        end
        
        WRITE: begin
            // Do nothing
        end
    endcase
end

endmodule