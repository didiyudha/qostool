# Check if an element is exist in a list or not
def find_elm_list(items, elm):
   if items:
      for item in items:
         if str(item).upper() == str(elm).upper():
	    return true
   return false

# Find Different element between two list
def find_differ_elm_list(first_list, second_list):
   temp = []
   for fl in first_list:
      if not find_elm_list(second_list, fl):
         temp.append(fl)
   return temp
