import csv
import os

class DDInterChecker:
    def __init__(self):
        # We use a dictionary for O(1) instant lookups instead of a list
        self.interaction_map = {} 
        self.all_drugs = []
        
        self.csv_path = self._find_csv()
        
        if self.csv_path:
            print(f"Loading database from: {self.csv_path}")
            self._load_data() # This now builds the dictionary
            self.all_drugs = sorted(list(self.all_drugs))
        else:
            print("⚠ WARNING: CSV not found. Loading Sample Data.")
            # FALLBACK DATA
            self.all_drugs = sorted([
                "Aspirin", "Warfarin", "Ibuprofen", "Tylenol", "Metformin", 
                "Lisinopril", "Simvastatin", "Omeprazole", "Amoxicillin"
            ])

    def _find_csv(self):
        """Aggressively looks for the CSV file."""
        filename = 'ddinter_ddi.csv'
        candidates = [
            os.path.join('data', filename),
            filename,
            os.path.join(os.getcwd(), 'data', filename),
            os.path.join(os.path.dirname(__file__), 'data', filename),
            os.path.join('..', 'data', filename)
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _load_data(self):
        """
        Loads CSV into a Dictionary for instant access.
        Key = (drug1, drug2) sorted alphabetically
        Value = Interaction Details
        """
        unique_drugs = set()
        try:
            with open(self.csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    d1 = row.get('Drug_A', '').strip()
                    d2 = row.get('Drug_B', '').strip()
                    
                    if d1 and d2:
                        unique_drugs.add(d1)
                        unique_drugs.add(d2)
                        
                        # Create a standardized key by sorting names
                        # This ensures (Aspirin, Warfarin) is the same key as (Warfarin, Aspirin)
                        key = tuple(sorted([d1.lower(), d2.lower()]))
                        
                        # Store the data
                        self.interaction_map[key] = {
                            'severity': row.get('Level', 'Unknown'),
                            'description': f"Interaction found between {d1} and {d2}"
                        }
                        
            self.all_drugs = unique_drugs
            
        except Exception as e:
            print(f"Error reading CSV: {e}")

    def get_drug_list(self):
        return self.all_drugs

    def check_interaction(self, drug_a, drug_b):
        found = []
        da = drug_a.strip().lower()
        db = drug_b.strip().lower()

        # 1. GENERATE KEY: Sort the inputs exactly like we did when loading
        key = tuple(sorted([da, db]))

        # 2. INSTANT LOOKUP: Check if this key exists in the dictionary
        if key in self.interaction_map:
            found.append(self.interaction_map[key])
        
        # 3. MOCK FALLBACK (Only if DB is empty/missing)
        if not self.interaction_map and not found:
            if (da == "aspirin" and db == "warfarin") or (da == "warfarin" and db == "aspirin"):
                found.append({
                    'severity': 'Major',
                    'description': 'Increased risk of bleeding (Mock Data).'
                })
                
        return found