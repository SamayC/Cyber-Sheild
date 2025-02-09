import numpy as np

# Transformation function
def transform_new_input(new_input):
    # Scaled minimum and maximum values from preprocessing
    scaled_min = np.array(
        [
            1.0,
            10.0,
            856.0,
            5775.0,
            42.0,
            26.0,
            0.0,
            278.0,
            4.0,
            1.0,
            -630355.0,
            4.0,
            50.0,
        ]
    )

    scaled_max = np.array(
        [
            4.0,
            352752.0,
            271591638.0,
            239241314.0,
            421552.0,
            3317.0,
            6302708.0,
            6302708.0,
            5.0,
            5.0,
            1746749.0,
            608.0,
            1012128.0,
        ]
    )

    new_input = np.array(new_input)

    # Formula for transformation
    scaled_input = (new_input - scaled_min) / (scaled_max - scaled_min)

    return scaled_input


# Reverse Transformation function
def reverse_transformation(scaled_input):
    # Scaled minimum and maximum values from preprocessing
    scaled_min = np.array(
        [
            1.0,
            10.0,
            856.0,
            5775.0,
            42.0,
            26.0,
            0.0,
            278.0,
            4.0,
            1.0,
            -630355.0,
            4.0,
            50.0,
        ]
    )

    scaled_max = np.array(
        [
            4.0,
            352752.0,
            271591638.0,
            239241314.0,
            421552.0,
            3317.0,
            6302708.0,
            6302708.0,
            5.0,
            5.0,
            1746749.0,
            608.0,
            1012128.0,
        ]
    )

    # Reverse the scaling transformation
    original_input = (scaled_input * (scaled_max - scaled_min)) + scaled_min

    return original_input.astype(int)  # Convert to integer


# Main
if __name__ == "__main__":
    # Example of input in scaled format
    test_input = [
       0.0,0.03003724891002999,0.7444674613441041,0.0012418594245579397,0.0051439327941738494,0.9969614099058036,8.8216049355293e-05,4.4109970281304196e-05,1.0,0.5,0.2651777120395237,0.0016556291390728483,0.018327470045818674
    ]

    print("Scaled input:")
    print(test_input)

    # Convert scaled input back to original values
    original_value = reverse_transformation(np.array(test_input))

    print("\nOriginal value (in integers):")
    print(original_value)
