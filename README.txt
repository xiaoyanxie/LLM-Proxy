To build and run:
1. Run "npm i" in root directory.
2. Install necessary python packages as specified in src/llm-server/requirements.txt.
3. Configure .env file to include proper api key and endpoint (possibly python server port).
4. Run ./run.sh <port> <ca_cert_path> <ca_key_path>, which builds and run the proxy automatically.

Dependency:
node 18.19.1+
python 3.12+

Main functionality:
-- Act as a basic MITM HTTPS proxy that intecepts HTTP and HTTPS traffic
-- For top-level HTML responses, it injects a compiled widget into the page that can be interacted with via UI

High-level widget behavior:
-- When you opened a new web page that is compatible, it will automatically triggers the LLM request for a comment of the content on the current viewed html
    - To view the generated comment, hover over the lightbulb that pops at top of the avatar
    - The comment is cached per page
-- Clicking the avatar toggles a menu
-- Clicking the ▶️ button in the menu starts a "session". Afterwards, the application will actively tracks your browsing activity and logs on backend. 
-- Clicking the 📝 button ends a "session" and generates LLM produced "session recap," which main goal is to provide a comprehensive study-oriented review based on your session activity.
-- Clicking the 💡 button re-generate a new comment over the current webpage and overwrites the old cache


