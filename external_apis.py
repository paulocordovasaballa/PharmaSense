import requests

class MedicalAPI:
    def __init__(self):
        self.session = requests.Session()

    def get_fda_warnings(self, drug_name):
        """
        Queries the OpenFDA government database for specific safety warnings.
        """
        clean_name = drug_name.strip()
        
        # OpenFDA API Endpoint
        url = f'https://api.fda.gov/drug/label.json?search=openfda.brand_name:"{clean_name}"+OR+openfda.generic_name:"{clean_name}"&limit=1'
        
        try:
            response = self.session.get(url, timeout=3)
            
            if response.status_code == 200:
                data = response.json()
                if 'results' in data:
                    result = data['results'][0]
                    
                    # 1. Check for "Boxed Warning"
                    if 'boxed_warning' in result:
                        return f"⚠ BLACK BOX WARNING: {result['boxed_warning'][0]}"
                    
                    # 2. Check general warnings
                    elif 'warnings' in result:
                        return f"FDA Safety Note: {result['warnings'][0]}"
            
            return None
            
        except requests.exceptions.RequestException:
            return "⚠ Internet Error: Could not fetch FDA data."
        except Exception as e:
            return None