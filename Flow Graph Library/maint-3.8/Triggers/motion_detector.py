import sys
import time

import cv2
import numpy as np


def main():
    # Accept Command Line Arguments
    try:
        motion_frame_threshold = int(sys.argv[1])
    except:
        print("Error accepting motion detector arguments. Exiting trigger.")
        return -1
            
    # Initialize motion detection variables
    motion_detected = False
    frame_count = 0
    #motion_frame_threshold = 30  # Number of consecutive frames with motion to trigger exit
    prev_frame = None

    while not motion_detected:
        # Capture frame
        frame = capture_frame()

        # Convert frame to grayscale
        frame_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Calculate difference between current frame and previous frame
        if prev_frame is not None:
            diff = cv2.absdiff(frame_gray, prev_frame)
            
            # Apply threshold to difference image
            _, diff_thresh = cv2.threshold(diff, 50, 255, cv2.THRESH_BINARY)
            
            # Perform morphological operations (dilation and erosion)
            kernel = np.ones((5, 5), np.uint8)
            diff_thresh = cv2.dilate(diff_thresh, kernel, iterations=2)
            diff_thresh = cv2.erode(diff_thresh, kernel, iterations=2)
            
            # Find contours of motion regions
            contours, _ = cv2.findContours(diff_thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Filter out small contours and calculate motion area
            motion_area = 0
            for contour in contours:
                if cv2.contourArea(contour) > 500:  # Adjust minimum motion area threshold
                    motion_area += cv2.contourArea(contour)
            
            # If motion area exceeds a threshold, consider it as motion
            if motion_area > 5000:  # Adjust minimum motion area threshold
                print("Motion detected! Exiting program.")
                motion_detected = True

        # Update previous frame
        prev_frame = frame_gray

        # Increment frame count
        frame_count += 1

        # Break loop if the number of frames exceeds the threshold
        if frame_count > motion_frame_threshold:
            return 0

        # Delay to limit frame rate (optional)
        time.sleep(0.1)

def capture_frame():
    # Capture frame from webcam
    cap = cv2.VideoCapture(0)  # Use 0 for the default webcam (usually built-in)
    ret, frame = cap.read()
    cap.release()
    return frame
    
if __name__ == "__main__":
    main()
