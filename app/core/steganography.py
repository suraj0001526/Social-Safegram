from stegano import lsb
import os

def hide_message(image_path: str, message: str, save_path: str):
    """
    Hides a secret message inside a PNG image.
    
    Args:
        image_path: Path to the original uploaded image.
        message: The secret text to hide.
        save_path: Where to save the new 'secret' image.
    """
    try:
        # Check if file exists
        if not os.path.exists(image_path):
            return {"status": "error", "message": "Input file not found."}

        # Attempt to hide message
        # 'lsb.hide' creates a new image object with the data
        secret_image = lsb.hide(image_path, message)
        
        # Save the result to the defined path
        secret_image.save(save_path)
        
        return {"status": "success", "output_path": save_path}

    except Exception as e:
        error_msg = str(e)
        # Common error: User uploads JPG instead of PNG
        if "unable to read" in error_msg.lower() or "cannot write" in error_msg.lower():
            return {"status": "error", "message": "Format Error: Please use a standard .PNG image."}
        
        print(f"Stego Hide Error: {e}")
        return {"status": "error", "message": f"Encryption failed: {error_msg}"}

def reveal_message(image_path: str):
    """
    Extracts a secret message from a PNG image.
    """
    try:
        if not os.path.exists(image_path):
            return {"status": "error", "message": "File not found."}

        # Attempt to reveal
        clear_message = lsb.reveal(image_path)
        
        if not clear_message:
            return {"status": "error", "message": "No hidden message found in this image."}
            
        return {"status": "success", "message": clear_message}

    except IndexError:
        return {"status": "error", "message": "No secret found (Index Error)."}
    except Exception as e:
        print(f"Stego Reveal Error: {e}")
        return {"status": "error", "message": "Could not decode. Ensure it is a PNG."}