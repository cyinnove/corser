package utils


func ElementExists(slice []string, element string) bool {
    for _, v := range slice {
        if v == element {
            return true
        }
    }
    return false
}