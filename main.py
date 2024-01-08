from flask import Flask, render_template, request, send_file
from BinaryFileIO import BinaryFileIO
from CodeSign import CodeSign
  
import os
 
keys_folder = 'Keys'
app = Flask(__name__)
def byteArray2Hex(bytearrdata):
    return bytearrdata.hex()

@app.route('/', methods=['GET', 'POST'])
def welcome():
    if request.method == 'POST':
        # Check if the 'file' key is in the request.files dictionary
        if 'file' not in request.files:
            return render_template('error.html', error_message="No file part")

        file = request.files['file']

        # Check if a file is selected
        if file.filename == '':
            return render_template('error.html', error_message="No file selected!!")

        # Save the uploaded file to a temporary location
        #file_path = 'temp_upload.bin'
        file_path = file.filename
        file.save(file_path)

        # Validate the binary file
        file_io = BinaryFileIO(file_path)
        if file_io.validate_binary():
            len= file_io.get_file_length()
            data_to_be_signed = file_io.get_code()
            #Load the keys
            private_key_path = os.path.join(keys_folder,"PrivKey_FIRMWARE.pem")            
            public_key_path = os.path.join(keys_folder,"PubKey_FIRMWARE.crt")
            code_signer = CodeSign(private_key_path, public_key_path)
            
            # Sign the uploaded file
            hash_value = code_signer.calc_hash(data_to_be_signed)
                
            signature = code_signer.sign_hash(hash_value)
            verification_result = code_signer.verify_signature(hash_value, signature)
 
            rollback_version = file_io.get_header_field('ROLLBACK_VER')
            sw_version = file_io.get_header_field('SW_VERSION')            
            uploaded_hash=  file_io.get_header_field('HASH')
            
            if (hash_value != uploaded_hash):                
                error_code= 0x2
                verification_result = False

        else:
            # Delete the file after processing
            #os.remove(file_path)
            error_code= 0x1
            verification_result = False            
        

        if verification_result:
            # Provide a button to download the signed file
            download_folder = "download"  # Specify the download folder
            file_io.create_copy()
            file_io.update_signature(signature)
            signed_file = "signed_" + file.filename
            download_link = f'<a href="/{download_folder}/{signed_file}" download="{signed_file}"><button id="download-button">Download Signed File</button></a>'
            print(download_link)       
            # Replace these with actual values or retrieve them from your application logic
            data = {
                'hash_value': byteArray2Hex(hash_value),
                'signature': byteArray2Hex(signature),
                'sw_version': byteArray2Hex(sw_version),
                'rollback_id': byteArray2Hex(rollback_version),
                'verification_result': verification_result,  
                'download_link': (download_link)
            }
            # Render the template with the hash value, signature, verification result, and download link
            return render_template('success.html', **data)                         
        else:
            #@TODO : Delete the uploaded File 
            # Delete the file after processing
            os.remove(file_path)
            # Return an error message indicating that the upload failed verification            
            if (error_code== 0x2):
                error_message = "Verification Failed: Calculated and Input HASH did not match !  "
            elif(error_code== 0x1):
                error_message = "Verification Failed: Header(0xCOFFEEEE) Missing"
        
            return render_template('error.html', error_message=error_message)        

    return render_template('welcome.html')

@app.route('/download/<filename>')
def download(filename):
    # Provide the option to download the signed file
    signed_file_path = f'{filename}'
 
    signed_file_path="download/"+signed_file_path
    return send_file(signed_file_path, as_attachment=True)


@app.route('/help')
def help():
    print("got called help ....")
    return render_template('help.html')

if __name__ == '__main__':
    #app.run(debug=True)
    #ssl_context = ('cert.pem', 'key.pem')
    app.run(host='10.1.13.63', port=5000, debug=True)
    #app.run(host='192.168.68.107', port=5000, debug=True)
    #app.run(host='10.1.13.63', port=5000, debug=True,ssl_context=ssl_context)
