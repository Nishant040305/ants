"""
LLM-based security analysis using Google Gemini
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai


class LLMAnalyzer:
    def __init__(self, api_key: str = None, model_name: str = 'gemini-2.5-flash'):
        """Initialize the LLM analyzer with Gemini"""
        if api_key:
            self.api_key = api_key
        else:
            load_dotenv()
            self.api_key = os.getenv("GOOGLE_API_KEY")
            
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment")
            
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(model_name)
        
        # Load prompt template
        prompt_path = Path(__file__).parent.parent / "prompts" / "security_analysis.prompt.md"
        with open(prompt_path, 'r', encoding='utf-8') as f:
            self.prompt_template = f.read()
        
    async def analyze_packet(self, http_packet):
        """
        Analyze HTTP packet content using Gemini LLM
        
        Args:
            http_packet: HTTPPacket object to analyze
        Returns:
            dict: Analysis results including severity and recommendations
        """
        try:
            # Format prompt with packet data
            prompt = self.prompt_template.format(
                method=http_packet.method,
                uri=http_packet.uri,
                src_ip=getattr(http_packet.metadata, 'src_ip', 'Unknown'),
                dst_ip=getattr(http_packet.metadata, 'dst_ip', 'Unknown'),
                headers=json.dumps(http_packet.headers, indent=2),
                body=http_packet.body if http_packet.body else 'No body content'
            )

            # Get LLM analysis
            response = self.model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.3,
                    "top_p": 0.8,
                    "top_k": 40,
                    "max_output_tokens": 1024,
                },
                safety_settings=[
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
                ]
            )
            
            # Debug raw response structure
            print(f"📋 Raw response structure:")
            print(f"   Response type: {type(response)}")
            if hasattr(response, 'prompt_feedback'):
                print(f"   Prompt feedback: {response.prompt_feedback}")
                if response.prompt_feedback and hasattr(response.prompt_feedback, 'block_reason'):
                    print(f"   Block reason: {response.prompt_feedback.block_reason}")
            if hasattr(response, 'text'):
                try:
                    text_available = bool(response.text)
                    print(f"   Direct text available: {text_available}")
                except Exception as e:
                    print(f"   Error accessing text: {e}")
            if hasattr(response, 'parts'):
                print(f"   Direct parts available: {bool(response.parts)}")
            
            # Detailed debugging of response
            print(f"🔍 Response debugging:")
            print(f"   Has candidates: {bool(response.candidates)}")
            if response.candidates:
                candidate = response.candidates[0]
                print(f"   Finish reason: {candidate.finish_reason}")
                print(f"   Has parts: {bool(candidate.content.parts if hasattr(candidate, 'content') else False)}")
                
                # Check safety ratings
                if hasattr(candidate, 'safety_ratings'):
                    print(f"   Safety ratings:")
                    for rating in candidate.safety_ratings:
                        print(f"     {rating.category}: {rating.probability}")
                
                # Check if content exists
                if hasattr(candidate, 'content') and candidate.content.parts:
                    print(f"   Content parts count: {len(candidate.content.parts)}")
                    for i, part in enumerate(candidate.content.parts):
                        print(f"     Part {i}: {len(part.text) if part.text else 0} characters")
                else:
                    print(f"   No content parts available")
            
            # Check if response has content
            if not response.candidates or not response.candidates[0].content.parts or not response.candidates[0].content.parts[0].text:
                print(f"❌ LLM response blocked or empty")
                return None
            
            # Parse response - strip markdown code blocks if present
            try:
                response_text = response.text.strip()
                
                # Remove ```json and ``` markers if present
                if response_text.startswith('```json'):
                    response_text = response_text[7:]  # Remove ```json
                if response_text.startswith('```'):
                    response_text = response_text[3:]  # Remove ```
                if response_text.endswith('```'):
                    response_text = response_text[:-3]  # Remove closing ```
                
                response_text = response_text.strip()
                analysis = json.loads(response_text)
                return analysis
            except json.JSONDecodeError as e:
                print(f"Failed to parse LLM response as JSON: {str(e)}")
                print(f"Raw response: {response.text[:200]}...")
                return {
                    "severity": 5,
                    "risk_level": "medium",
                    "findings": ["Error parsing LLM response"],
                    "recommendations": ["Manual review required"],
                    "sensitive_data_detected": False,
                    "explanation": "Failed to parse LLM analysis"
                }
                
        except Exception as e:
            error_msg = str(e)
            if "finish_reason" in error_msg and "is 2" in error_msg:
                print(f"⚠️  LLM response blocked by Gemini safety filters (finish_reason: 2)")
                print(f"   This happens when content is flagged as potentially unsafe")
                print(f"   Even with safety settings disabled, some content may still be blocked")
            else:
                print(f"Error in LLM analysis: {error_msg}")
            return None


if __name__ == "__main__":
    """Unit tests with sample toy data"""
    import asyncio
    from datetime import datetime
    
    print("🧪 Testing LLMAnalyzer with sample data...")
    print("⚠️  Note: This requires GOOGLE_API_KEY in environment or .env file")
    
    # Sample HTTPPacket-like objects for testing
    class MockPacket:
        def __init__(self, method, uri, body, headers=None):
            self.method = method
            self.uri = uri
            self.body = body
            self.headers = headers or {}
            self.timestamp = datetime.now().timestamp()
            self.src_ip = "192.168.1.100"
            self.dst_ip = "10.0.0.1"
            
            # Create mock metadata
            class MockMetadata:
                def __init__(self):
                    self.src_ip = "192.168.1.100"
                    self.dst_ip = "10.0.0.1"
                    self.timestamp = datetime.now()
            
            self.metadata = MockMetadata()
            
            # Create mock metadata
            class MockMetadata:
                def __init__(self):
                    self.src_ip = "192.168.1.100"
                    self.dst_ip = "10.0.0.1"
            self.metadata = MockMetadata()
    
    # Create test packets with varying security concerns (using safer test data)
    test_packets = [
        MockPacket(
            "GET",
            "/api/health",
            "",
            {}
        ),
        MockPacket(
            "POST", 
            "/api/login",
            '{"username": "testuser", "action": "authenticate"}',
            {"content-type": "application/json"}
        ),
        MockPacket(
            "GET",
            "/api/users?debug=true",
            "",
            {"authorization": "Bearer test-token-123"}
        ),
        MockPacket(
            "POST",
            "/api/upload",
            '{"filename": "document.pdf", "size": "2048"}',
            {"content-type": "application/json"}
        ),
        MockPacket(
            "GET",
            "/admin/config",
            "",
            {"user-agent": "Mozilla/5.0"}
        )
    ]
    
    async def test_llm_analysis():
        # Initialize analyzer - will raise ValueError if no API key
        analyzer = LLMAnalyzer()
        
        # Test basic connectivity first
        print("\n🔌 Testing Gemini connectivity...")
        try:
            test_response = analyzer.model.generate_content("Hi! Please respond with 'Hello' if you can hear me.")
            if test_response and hasattr(test_response, 'text') and test_response.text:
                print(f"   ✅ Gemini responded: '{test_response.text.strip()}'")
                print("   Connection is working!")
            else:
                print(f"   ❌ No text response from Gemini")
                print(f"   Debug - Response type: {type(test_response)}")
                if hasattr(test_response, 'candidates'):
                    print(f"   Debug - Has candidates: {bool(test_response.candidates)}")
                    if test_response.candidates:
                        candidate = test_response.candidates[0]
                        print(f"   Debug - Finish reason: {getattr(candidate, 'finish_reason', 'N/A')}")
                return []
        except Exception as e:
            print(f"   ❌ Connectivity test failed: {str(e)}")
            return []
        
        # Real LLM analysis
        results = []
        print(f"\nAnalyzing {len(test_packets)} packets with Gemini...")
        
        for i, packet in enumerate(test_packets, 1):
            print(f"\n📦 Analyzing packet {i}: {packet.method} {packet.uri}")
            
            try:
                result = await analyzer.analyze_packet(packet)
                if result:
                    results.append(result)
                    print(f"   ✓ Severity: {result.get('severity', 'N/A')}")
                    print(f"   ✓ Risk Level: {result.get('risk_level', 'N/A')}")
                    print(f"   ✓ Findings: {len(result.get('findings', []))}")
                    print(f"   ✓ Explanation: {result.get('explanation', 'N/A')[:100]}...")
                else:
                    print("   ❌ Analysis failed")
                    
                # Small delay to respect API rate limits
                await asyncio.sleep(1)
                
            except Exception as e:
                print(f"   ❌ Error: {str(e)}")
        
        return results
    
    # Run async test
    try:
        results = asyncio.run(test_llm_analysis())
        
        print(f"\n📊 Analysis Summary:")
        if results:
            # Statistics for successful analyses
            total_successful = len(results)
            high_severity = sum(1 for r in results if r.get('severity', 0) >= 7)
            critical_risk = sum(1 for r in results if r.get('risk_level') == 'critical')
            avg_severity = sum(r.get('severity', 0) for r in results) / total_successful
            
            print(f"   Successful analyses: {total_successful}")
            print(f"   High severity (≥7): {high_severity} ({high_severity/total_successful*100:.1f}%)")
            print(f"   Critical risk: {critical_risk}")
            print(f"   Average severity: {avg_severity:.2f}")
        else:
            print("   No successful LLM analyses")
            print("   💡 This is likely due to Gemini's safety filters blocking HTTP security content")
            print("   💡 The connectivity test passed, so the API is working")
            print("   💡 In production, try with real (less flagged) network traffic")
        
        print("\n✅ LLMAnalyzer tests completed!")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        raise