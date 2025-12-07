import requests

class MedicalAPI:
    def __init__(self):
        self.session = requests.Session()

    def get_fda_warnings(self, drug_name):
        """
        Queries the OpenFDA government database for specific safety warnings.
        Returns a string if a Boxed Warning (Black Box) is found.
        """
        # Clean the input (e.g., "Aspirin " -> "Aspirin")
        clean_name = drug_name.strip()
        
        # OpenFDA API Endpoint (No Key Required)
        # We search for the brand_name OR generic_name matching our drug
        url = f'https://api.fda.gov/drug/label.json?search=openfda.brand_name:"{clean_name}"+OR+openfda.generic_name:"{clean_name}"&limit=1'
        
        try:
            response = self.session.get(url, timeout=3) # 3 second timeout so app doesn't freeze
            
            if response.status_code == 200:
                data = response.json()
                if 'results' in data:
                    result = data['results'][0]
                    
                    # 1. Check for "Boxed Warning" (The most severe type)
                    if 'boxed_warning' in result:
                        warning_text = result['boxed_warning'][0]
                        return f"⚠ BLACK BOX WARNING: {warning_text[:300]}..." # Limit length
                    
                    # 2. If no boxed warning, check generally
                    elif 'warnings' in result:
                        return f"FDA Safety Note: {result['warnings'][0][:200]}..."
            
            return None # No specific warnings found or drug not in FDA DB
            
        except requests.exceptions.RequestException:
            return "⚠ Internet Error: Could not fetch FDA data."
        except Exception as e:
            return None